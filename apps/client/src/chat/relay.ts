// 与后端 WebSocket 中继的连接封装。负载为不透明 base64 密文。

import { WS_BASE_URL } from "../config";

export interface WsEnvelope {
  type: string; // "message" | "ack" | "receipt" | "typing" | "recall"
  id?: string;
  client_ref?: string;
  from?: string;
  envelope_type?: string;
  payload?: string; // base64 密文
  created_at?: number;
  status?: string;
  message_id?: string;
  typing?: boolean;
  group_id?: string;
  error?: string;
}

export type RelayStatus = "connecting" | "connected" | "disconnected";

const MAX_BACKOFF_MS = 30_000;

export class RelayClient {
  private ws: WebSocket | null = null;
  private closed = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private attempts = 0;

  /**
   * @param getToken 每次(重)连前调用,返回当前有效的访问令牌。
   *                 访问令牌有效期很短,重连时必须取最新的(必要时先刷新),不能沿用旧令牌。
   */
  constructor(
    private readonly getToken: () => Promise<string | null>,
    private readonly onEnvelope: (env: WsEnvelope) => void,
    private readonly onStatus: (status: RelayStatus) => void,
  ) {}

  connect(): void {
    if (this.closed) return;
    void this.open();
  }

  private async open(): Promise<void> {
    this.onStatus("connecting");
    const token = await this.getToken().catch(() => null);
    if (this.closed) return;
    if (!token) {
      this.onStatus("disconnected");
      this.scheduleReconnect();
      return;
    }

    const ws = new WebSocket(`${WS_BASE_URL}/api/v1/ws?token=${encodeURIComponent(token)}`);
    this.ws = ws;
    ws.onopen = () => {
      this.attempts = 0;
      this.onStatus("connected");
    };
    ws.onmessage = (ev) => {
      try {
        this.onEnvelope(JSON.parse(ev.data));
      } catch {
        // 忽略无法解析的帧
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws) return; // 已被替换或主动关闭
      this.ws = null;
      this.onStatus("disconnected");
      this.scheduleReconnect();
    };
  }

  // 指数退避重连(1s, 2s, 4s … 上限 30s)
  private scheduleReconnect(): void {
    if (this.closed || this.timer) return;
    const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** this.attempts);
    this.attempts++;
    this.timer = setTimeout(() => {
      this.timer = null;
      if (!this.closed) void this.open();
    }, delay);
  }

  private rawSend(obj: Record<string, unknown>): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    this.ws.send(JSON.stringify(obj));
    return true;
  }

  send(to: string, envelopeType: string, payload: string, clientRef: string, groupId?: string): boolean {
    const msg: Record<string, unknown> = {
      type: "send",
      to,
      envelope_type: envelopeType,
      payload,
      client_ref: clientRef,
    };
    if (groupId) msg.group_id = groupId;
    return this.rawSend(msg);
  }

  sendReadReceipt(to: string, messageId: string): void {
    this.rawSend({ type: "receipt", to, message_id: messageId, status: "read" });
  }

  sendTyping(to: string, typing: boolean): void {
    this.rawSend({ type: "typing", to, typing });
  }

  sendRecall(to: string, messageId: string): boolean {
    return this.rawSend({ type: "recall", to, message_id: messageId });
  }

  /** 主动关闭:取消挂起的重连,之后不再自动重连(登出/卸载时调用)。 */
  close(): void {
    this.closed = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const ws = this.ws;
    this.ws = null;
    ws?.close();
  }
}
