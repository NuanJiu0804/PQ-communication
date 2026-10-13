package messaging

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/pqchat/server/internal/validate"
)

// MaxPayloadBytes 单条密文负载上限。文本与媒体描述符远小于此;
// 媒体本体走对象存储,不经过 WebSocket。
const MaxPayloadBytes = 64 * 1024

// MaxFrameBytes WebSocket 单帧读取上限(负载经 base64 膨胀约 4/3,另含 JSON 字段)。
const MaxFrameBytes = 128 * 1024

// inbound 客户端 → 服务器。
// Type: send(发消息)| receipt(已读回执)| typing(正在输入)| recall(撤回)
type inbound struct {
	Type         string `json:"type"`
	ClientRef    string `json:"client_ref"`
	To           string `json:"to"`
	EnvelopeType string `json:"envelope_type"` // prekey | message
	Payload      []byte `json:"payload"`       // 不透明密文(JSON 自动 base64)
	MessageID    string `json:"message_id"`    // receipt / recall 针对的信封 ID
	Status       string `json:"status"`        // receipt: read
	Typing       bool   `json:"typing"`        // typing: 是否正在输入
	GroupID      string `json:"group_id"`      // 群消息所属群 id(成对扇出时每条都带)
}

// outbound 服务器 → 客户端。
// Type: message(转发信封)| ack(发送回执)| receipt(送达/已读)| typing | recall
type outbound struct {
	Type         string `json:"type"`
	ID           string `json:"id,omitempty"`
	ClientRef    string `json:"client_ref,omitempty"`
	From         string `json:"from,omitempty"`
	EnvelopeType string `json:"envelope_type,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
	Status       string `json:"status,omitempty"`
	Error        string `json:"error,omitempty"`
	MessageID    string `json:"message_id,omitempty"`
	Typing       bool   `json:"typing,omitempty"`
	GroupID      string `json:"group_id,omitempty"`
}

// Client 一个在线连接。
type Client struct {
	userID string
	send   chan outbound
	cancel context.CancelFunc // 断开该连接(封禁踢下线时使用)
}

func (c *Client) trySend(env outbound) bool {
	select {
	case c.send <- env:
		return true
	default:
		return false
	}
}

// Hub 维护在线连接并负责路由。
type Hub struct {
	mu      sync.RWMutex
	clients map[string]map[*Client]bool
	repo    *Repo
	logger  *slog.Logger
}

// NewHub 创建中继 Hub。
func NewHub(repo *Repo, logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[string]map[*Client]bool),
		repo:    repo,
		logger:  logger,
	}
}

func (h *Hub) add(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.userID] == nil {
		h.clients[c.userID] = make(map[*Client]bool)
	}
	h.clients[c.userID][c] = true
}

func (h *Hub) remove(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.clients[c.userID]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(h.clients, c.userID)
		}
	}
}

// deliver 把信封推给在线接收方的所有连接,返回是否至少投递给一个连接。
func (h *Hub) deliver(recipientID string, env outbound) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	set := h.clients[recipientID]
	delivered := false
	for c := range set {
		if c.trySend(env) {
			delivered = true
		}
	}
	return delivered
}

// IsOnline 判断用户是否有在线连接。
func (h *Hub) IsOnline(userID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients[userID]) > 0
}

// Kick 断开某用户的全部在线连接(例如账号被封禁)。
func (h *Hub) Kick(userID string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients[userID] {
		if c.cancel != nil {
			c.cancel()
		}
	}
}

// OnlineCount 当前在线用户数(去重)。
func (h *Hub) OnlineCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Serve 处理一条已升级的 WebSocket 连接,直到断开。
func (h *Hub) Serve(ctx context.Context, userID string, conn *websocket.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn.SetReadLimit(MaxFrameBytes)

	client := &Client{userID: userID, send: make(chan outbound, 64), cancel: cancel}
	h.add(client)
	defer h.remove(client)

	writeCtx, cancelWrite := context.WithCancel(ctx)
	defer cancelWrite()

	// 写泵:把待发消息写到连接;成功写出 message 类型后把信封标记为已投递。
	go func() {
		for {
			select {
			case <-writeCtx.Done():
				return
			case env := <-client.send:
				wctx, cancel := context.WithTimeout(writeCtx, 10*time.Second)
				err := wsjson.Write(wctx, conn, env)
				cancel()
				if err != nil {
					// 写失败即视为连接已坏:断开整条连接,让客户端重连后从离线队列补收,
					// 避免读循环仍在而写泵已退出、后续消息被「静默吞掉」。
					conn.CloseNow()
					return
				}
				if env.Type == "message" && env.ID != "" {
					if err := h.repo.MarkDelivered(context.Background(), env.ID); err != nil {
						h.logger.Warn("标记已投递失败", "id", env.ID, "error", err.Error())
					}
				}
			}
		}
	}()

	// 上线即补发离线消息
	h.flushOffline(ctx, client)

	h.logger.Info("WS 已连接", "user_id", userID)

	// 读泵:阻塞直到断开
	for {
		var msg inbound
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			break
		}
		h.dispatch(ctx, client, &msg)
	}
	h.logger.Info("WS 已断开", "user_id", userID)
}

func (h *Hub) dispatch(ctx context.Context, client *Client, msg *inbound) {
	switch msg.Type {
	case "send":
		h.handleSend(ctx, client, msg)
	case "receipt":
		h.handleReceipt(ctx, client, msg)
	case "typing":
		h.handleTyping(ctx, client, msg)
	case "recall":
		h.handleRecall(ctx, client, msg)
	default:
		client.trySend(outbound{Type: "ack", ClientRef: msg.ClientRef, Status: "error", Error: "未知的消息类型"})
	}
}

func (h *Hub) handleSend(ctx context.Context, client *Client, msg *inbound) {
	fail := func(reason string) {
		client.trySend(outbound{Type: "ack", ClientRef: msg.ClientRef, Status: "error", Error: reason})
	}
	if !validate.UUID(msg.To) || len(msg.Payload) == 0 || (msg.GroupID != "" && !validate.UUID(msg.GroupID)) {
		fail("无效的发送请求")
		return
	}
	if len(msg.Payload) > MaxPayloadBytes {
		fail("消息过大")
		return
	}
	envType := msg.EnvelopeType
	if envType == "" {
		envType = "message"
	}
	if envType != "prekey" && envType != "message" {
		fail("未知的信封类型")
		return
	}
	if err := h.repo.CheckDeliverable(ctx, client.userID, msg.To, msg.GroupID); err != nil {
		if errors.Is(err, ErrRecipientNotFound) || errors.Is(err, ErrBlocked) || errors.Is(err, ErrNotGroupMember) {
			fail(err.Error())
			return
		}
		h.logger.Error("投递前校验失败", "error", err.Error())
		fail("服务器内部错误")
		return
	}

	id, createdAt, err := h.repo.Insert(ctx, client.userID, msg.To, envType, msg.GroupID, msg.Payload)
	if err != nil {
		h.logger.Error("存储信封失败", "error", err.Error())
		client.trySend(outbound{Type: "ack", ClientRef: msg.ClientRef, Status: "error", Error: "服务器内部错误"})
		return
	}

	relayed := outbound{
		Type:         "message",
		ID:           id,
		From:         client.userID,
		EnvelopeType: envType,
		Payload:      msg.Payload,
		CreatedAt:    createdAt.UnixMilli(),
		GroupID:      msg.GroupID,
	}

	status := "queued"
	if h.deliver(msg.To, relayed) {
		status = "delivered"
	}
	client.trySend(outbound{
		Type:      "ack",
		ClientRef: msg.ClientRef,
		ID:        id,
		Status:    status,
		CreatedAt: createdAt.UnixMilli(),
	})
}

// handleReceipt 处理已读回执:仅信封的接收方可标记已读,回执发给信封的真实发送者
// (不信任客户端给出的 to,防止伪造他人消息的已读状态或向任意用户推送回执)。
func (h *Hub) handleReceipt(ctx context.Context, client *Client, msg *inbound) {
	if !validate.UUID(msg.MessageID) || msg.Status != "read" {
		return
	}
	senderID, ok, err := h.repo.MarkRead(ctx, msg.MessageID, client.userID)
	if err != nil {
		h.logger.Warn("标记已读失败", "id", msg.MessageID, "error", err.Error())
		return
	}
	if !ok {
		return
	}
	h.deliver(senderID, outbound{Type: "receipt", From: client.userID, MessageID: msg.MessageID, Status: "read"})
}

// handleTyping 转发正在输入状态(不持久化);存在拉黑关系时不转发。
func (h *Hub) handleTyping(ctx context.Context, client *Client, msg *inbound) {
	if !validate.UUID(msg.To) || msg.To == client.userID {
		return
	}
	if blocked, err := h.repo.IsBlocked(ctx, client.userID, msg.To); err != nil || blocked {
		return
	}
	h.deliver(msg.To, outbound{Type: "typing", From: client.userID, Typing: msg.Typing})
}

// handleRecall 处理撤回:仅发送者可撤回,清空服务端密文,并通知该信封的真实接收方。
func (h *Hub) handleRecall(ctx context.Context, client *Client, msg *inbound) {
	if !validate.UUID(msg.MessageID) {
		return
	}
	recipientID, ok, err := h.repo.MarkRecalled(ctx, msg.MessageID, client.userID)
	if err != nil {
		h.logger.Warn("撤回失败", "id", msg.MessageID, "error", err.Error())
		return
	}
	if !ok {
		return // 非本人消息或已撤回
	}
	h.deliver(recipientID, outbound{Type: "recall", From: client.userID, MessageID: msg.MessageID})
}

// flushOffline 按时间顺序补发离线信封。必须阻塞式写入发送队列:若队列满就丢弃,
// 被丢的握手消息会晚于后续消息到达,接收方将无法建立会话。
func (h *Hub) flushOffline(ctx context.Context, client *Client) {
	envelopes, err := h.repo.Queued(ctx, client.userID)
	if err != nil {
		h.logger.Error("拉取离线信封失败", "error", err.Error())
		return
	}
	for _, e := range envelopes {
		env := outbound{
			Type:         "message",
			ID:           e.ID,
			From:         e.SenderID,
			EnvelopeType: e.EnvelopeType,
			Payload:      e.Ciphertext,
			CreatedAt:    e.CreatedAt.UnixMilli(),
			GroupID:      e.GroupID,
		}
		select {
		case client.send <- env:
		case <-ctx.Done():
			return
		}
		// 通知原发送者:此前离线的消息已送达
		h.deliver(e.SenderID, outbound{
			Type:      "receipt",
			From:      client.userID,
			MessageID: e.ID,
			Status:    "delivered",
		})
	}
}
