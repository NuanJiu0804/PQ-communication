import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import {
  LogOut,
  ShieldAlert,
  ShieldCheck,
  Send,
  Plus,
  X,
  MessageSquare,
  Users,
  Paperclip,
  FileText,
  Download,
} from "lucide-react";

import { Button } from "../components/Button";
import { TextField } from "../components/TextField";
import { errorMessage } from "../api/client";
import { listFriends } from "../api/social";
import type { Profile } from "../api/social";

import { getDownloadUrl } from "../api/media";
import { useAuth } from "../auth/AuthContext";
import { useChat } from "../chat/ChatContext";
import { MAX_TEXT_LENGTH } from "../chat/ChatContext";
import type { ChatMessage, MediaDescriptor, MessageStatus } from "../chat/ChatContext";
import type { Group, GroupMember } from "../api/groups";
import { mediaDecrypt } from "../crypto/core";
import { base64ToBytes, bytesToBase64 } from "../util/bytes";
import { ContactsPanel } from "./ContactsPanel";

const shortId = (id: string) => id.slice(0, 8);
const isGroupKey = (k: string) => k.startsWith("g:");
const groupIdOf = (k: string) => k.slice(2);

// 下载并解密媒体密文,返回明文字节(供预览或下载使用)。
async function loadMedia(media: MediaDescriptor): Promise<Uint8Array<ArrayBuffer>> {
  const { download_url } = await getDownloadUrl(media.object_key);
  const res = await fetch(download_url);
  if (!res.ok) throw new Error("媒体下载失败");
  const cipherBytes = new Uint8Array(await res.arrayBuffer());
  const plainB64 = await mediaDecrypt(bytesToBase64(cipherBytes), media.key, media.nonce);
  return base64ToBytes(plainB64);
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function convMeta(key: string, groups: Group[], profiles: Record<string, Profile>) {
  if (isGroupKey(key)) {
    const g = groups.find((x) => x.id === groupIdOf(key));
    const name = g ? g.name : "群组";
    return { label: name, initial: name.slice(0, 1).toUpperCase(), isGroup: true, named: true };
  }
  const nick = profiles[key]?.nickname;
  return nick
    ? { label: nick, initial: nick.slice(0, 1).toUpperCase(), isGroup: false, named: true }
    : { label: `${shortId(key)}…`, initial: key.slice(0, 1).toUpperCase(), isGroup: false, named: false };
}

export function MainScreen() {
  const { status, error } = useChat();

  if (status === "unsupported") {
    return (
      <div className="chat-unsupported">
        <ShieldCheck size={40} aria-hidden />
        <h2>聊天功能需在桌面应用中使用</h2>
        <p>
          端到端加密在本地 Rust 核心完成,浏览器预览无法访问。请用
          <code className="mono"> npm run tauri dev </code>
          启动桌面应用(可开两个实例互相收发)。
        </p>
      </div>
    );
  }

  if (status === "initializing") {
    return <div className="chat-center">正在初始化密钥与连接…</div>;
  }

  if (status === "error") {
    return <div className="chat-center chat-error">初始化失败:{error}</div>;
  }

  return (
    <div className="chat-layout">
      <Sidebar />
      <ChatPane />
    </div>
  );
}

function Sidebar() {
  const { user, doLogout } = useAuth();
  const { conversations, unread, activePeer, selectPeer, groups, profiles } = useChat();
  const convKeys = useMemo(() => Object.keys(conversations), [conversations]);
  const [sideTab, setSideTab] = useState<"chats" | "contacts" | "groups">("chats");

  return (
    <aside className="chat-sidebar">
      <div className="self-card">
        <div className="avatar avatar-sm" aria-hidden>
          {user?.nickname.trim().slice(0, 1).toUpperCase() || "?"}
        </div>
        <div className="self-meta">
          <div className="self-name">{user?.nickname}</div>
          <div className="self-id mono" title={user?.id}>
            我的 ID:{shortId(user?.id ?? "")}…
          </div>
        </div>
        <button className="icon-button" onClick={() => void doLogout()} title="退出登录" aria-label="退出登录">
          <LogOut size={18} aria-hidden />
        </button>
      </div>

      <div className="side-tabs">
        <button className={sideTab === "chats" ? "side-tab active" : "side-tab"} onClick={() => setSideTab("chats")}>
          会话
        </button>
        <button className={sideTab === "contacts" ? "side-tab active" : "side-tab"} onClick={() => setSideTab("contacts")}>
          联系人
        </button>
        <button className={sideTab === "groups" ? "side-tab active" : "side-tab"} onClick={() => setSideTab("groups")}>
          群组
        </button>
      </div>

      {sideTab === "contacts" && <ContactsPanel />}
      {sideTab === "groups" && <GroupsPanel />}
      {sideTab === "chats" && (
        <>
          <NewChatForm />
          <div className="conv-list">
            {convKeys.length === 0 ? (
              <div className="conv-empty">还没有会话。从「联系人」或「群组」发起,或在下方输入对方 ID。</div>
            ) : (
              convKeys.map((key) => {
                const msgs = conversations[key];
                const last = msgs[msgs.length - 1];
                const count = unread[key] ?? 0;
                const meta = convMeta(key, groups, profiles);
                return (
                  <button
                    key={key}
                    className={key === activePeer ? "conv-item active" : "conv-item"}
                    onClick={() => selectPeer(key)}
                  >
                    <span className="avatar avatar-xs" aria-hidden>
                      {meta.isGroup ? <Users size={15} aria-hidden /> : meta.initial}
                    </span>
                    <span className="conv-text">
                      <span className={meta.named ? "conv-id" : "conv-id mono"}>{meta.label}</span>
                      <span className="conv-preview">
                        {last ? (last.recalled ? "已撤回一条消息" : last.system ? `[提示] ${last.text}` : last.text) : "新会话"}
                      </span>
                    </span>
                    {count > 0 ? <span className="unread-badge">{count}</span> : null}
                  </button>
                );
              })
            )}
          </div>
        </>
      )}
    </aside>
  );
}

function NewChatForm() {
  const { openChat } = useChat();
  const [peerId, setPeerId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await openChat(peerId);
      setPeerId("");
    } catch (e2) {
      setErr(errorMessage(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="new-chat" onSubmit={onSubmit}>
      <TextField
        label="发起会话"
        name="peerId"
        mono
        placeholder="粘贴对方用户 ID"
        value={peerId}
        onChange={(e) => setPeerId(e.target.value)}
      />
      {err ? <div className="new-chat-error">{err}</div> : null}
      <Button type="submit" variant="ghost" loading={busy} className="new-chat-btn">
        <Plus size={16} aria-hidden /> 开始
      </Button>
    </form>
  );
}

function GroupsPanel() {
  const { groups, openGroup, refreshGroups } = useChat();

  // 每次打开面板都刷新:群可能是别人新建并把我拉进去的
  useEffect(() => {
    refreshGroups().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [creating, setCreating] = useState(false);

  return (
    <div className="contacts">
      <div className="add-friend">
        {creating ? (
          <CreateGroupForm onDone={() => setCreating(false)} />
        ) : (
          <Button variant="ghost" className="new-chat-btn" onClick={() => setCreating(true)}>
            <Plus size={16} aria-hidden /> 新建群组
          </Button>
        )}
      </div>
      <div className="contacts-list">
        {groups.length === 0 ? (
          <div className="conv-empty">还没有群组。点上方「新建群组」。</div>
        ) : (
          groups.map((g) => (
            <div key={g.id} className="contact-item">
              <span className="avatar avatar-xs" aria-hidden>
                <Users size={15} aria-hidden />
              </span>
              <span className="contact-text">
                <span className="contact-name">{g.name}</span>
                <span className="contact-status">{g.member_count} 名成员</span>
              </span>
              <button className="icon-button-sm" onClick={() => void openGroup(g.id)} title="进入群聊">
                <MessageSquare size={15} aria-hidden />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function CreateGroupForm({ onDone }: { onDone: () => void }) {
  const { createGroupChat } = useChat();
  const [name, setName] = useState("");
  const [friends, setFriends] = useState<Profile[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    listFriends()
      .then((r) => setFriends(r.friends))
      .catch(() => undefined);
  }, []);

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await createGroupChat(name.trim(), [...selected]);
      onDone();
    } catch (e2) {
      setErr(errorMessage(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="create-group" onSubmit={submit}>
      <TextField label="群名称" name="gname" value={name} onChange={(e) => setName(e.target.value)} placeholder="给群起个名字" />
      <div className="member-pick">
        {friends.length === 0 ? (
          <span className="muted">先在「联系人」添加好友</span>
        ) : (
          friends.map((f) => (
            <label key={f.id} className="member-opt">
              <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggle(f.id)} />
              {f.nickname}
            </label>
          ))
        )}
      </div>
      {err ? <div className="new-chat-error">{err}</div> : null}
      <div className="create-group-actions">
        <Button type="button" variant="ghost" onClick={onDone}>
          取消
        </Button>
        <Button type="submit" loading={busy} disabled={!name.trim()}>
          创建
        </Button>
      </div>
    </form>
  );
}

function ChatPane() {
  const { user } = useAuth();
  const {
    activePeer,
    conversations,
    sendMessage,
    sendMedia,
    recallMessage,
    notifyTyping,
    typingPeers,
    presence,
    groups,
    groupMembers,
    profiles,
  } = useChat();
  const [draft, setDraft] = useState("");
  const [showSafety, setShowSafety] = useState(false);
  const [composerErr, setComposerErr] = useState<string | null>(null);
  const [sendingMedia, setSendingMedia] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const messages = activePeer ? conversations[activePeer] ?? [] : [];

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
  }, [messages.length, activePeer]);

  if (!activePeer) {
    return <div className="chat-pane chat-center">选择左侧会话,或从联系人/群组发起加密聊天。</div>;
  }

  const isGroup = isGroupKey(activePeer);
  const gid = isGroup ? groupIdOf(activePeer) : "";
  const group = isGroup ? groups.find((g) => g.id === gid) : undefined;
  const members: GroupMember[] = isGroup ? groupMembers[gid] ?? [] : [];
  const memberName = (id?: string) => members.find((m) => m.id === id)?.nickname ?? (id ? `${shortId(id)}…` : "");

  const peerOnline = presence[activePeer] ?? false;
  const peerTyping = !isGroup && (typingPeers[activePeer] ?? false);

  const onSend = async (e: FormEvent) => {
    e.preventDefault();
    const text = draft;
    setDraft("");
    setComposerErr(null);
    try {
      await sendMessage(text);
    } catch (err) {
      setComposerErr(errorMessage(err));
    }
  };

  const onPickFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = ""; // 允许再次选择同一文件
    if (!file) return;
    setComposerErr(null);
    setSendingMedia(true);
    try {
      await sendMedia(file);
    } catch (err) {
      setComposerErr(errorMessage(err));
    } finally {
      setSendingMedia(false);
    }
  };

  return (
    <section className="chat-pane">
      <header className="chat-header">
        <div className="chat-peer">
          <span className="avatar avatar-xs" aria-hidden>
            {isGroup ? <Users size={15} aria-hidden /> : convMeta(activePeer, groups, profiles).initial}
          </span>
          {isGroup ? (
            <>
              <span>{group ? group.name : "群组"}</span>
              <span className="peer-presence">{group ? `${group.member_count} 名成员` : ""}</span>
            </>
          ) : (
            <>
              <span className={profiles[activePeer] ? undefined : "mono"} title={activePeer}>
                {convMeta(activePeer, groups, profiles).label}
              </span>
              <span className={`relay-dot ${peerOnline ? "relay-connected" : "relay-disconnected"}`} aria-hidden />
              <span className="peer-presence">{peerOnline ? "在线" : "离线"}</span>
            </>
          )}
        </div>
        {!isGroup ? (
          <button className="icon-button" onClick={() => setShowSafety(true)} title="安全号码" aria-label="安全号码">
            <ShieldCheck size={18} aria-hidden />
          </button>
        ) : null}
      </header>

      <div className="msg-list" ref={listRef}>
        {messages.map((m) => (
          <MessageBubble
            key={m.id}
            message={m}
            onRecall={() => recallMessage(m.id)}
            senderName={isGroup && m.dir === "in" && m.senderId !== user?.id ? memberName(m.senderId) : undefined}
          />
        ))}
      </div>

      {peerTyping ? <div className="typing-indicator">对方正在输入…</div> : null}
      {composerErr ? <div className="composer-error">{composerErr}</div> : null}

      <form className="composer" onSubmit={onSend}>
        <input ref={fileRef} type="file" hidden onChange={onPickFile} />
        <button
          type="button"
          className="icon-button composer-attach"
          onClick={() => fileRef.current?.click()}
          disabled={sendingMedia}
          title="发送图片或文件"
          aria-label="发送图片或文件"
        >
          <Paperclip size={18} aria-hidden />
        </button>
        <input
          className="composer-input"
          placeholder={sendingMedia ? "正在加密上传媒体…" : "输入消息,回车发送…"}
          maxLength={MAX_TEXT_LENGTH}
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            notifyTyping();
          }}
        />
        <Button type="submit" disabled={!draft.trim()} className="composer-send" aria-label="发送">
          <Send size={16} aria-hidden />
        </Button>
      </form>

      {showSafety ? <SafetyNumberModal peerId={activePeer} onClose={() => setShowSafety(false)} /> : null}
    </section>
  );
}

function MessageBubble({
  message,
  onRecall,
  senderName,
}: {
  message: ChatMessage;
  onRecall: () => void;
  senderName?: string;
}) {
  const canRecall = message.dir === "out" && !message.recalled && !!message.serverId;

  if (message.system) {
    return (
      <div className="msg-system" role="status">
        <ShieldAlert size={14} aria-hidden />
        <span>{message.text}</span>
      </div>
    );
  }

  return (
    <div className={`bubble bubble-${message.dir}`}>
      {message.recalled ? (
        <div className="bubble-recalled">该消息已撤回</div>
      ) : (
        <>
          {senderName ? <div className="bubble-sender">{senderName}</div> : null}
          {message.media ? (
            <MediaContent media={message.media} />
          ) : (
            <div className="bubble-text">{message.text}</div>
          )}
          <div className="bubble-meta">
            {new Date(message.at).toLocaleTimeString()}
            {message.dir === "out" && message.status ? (
              <span className="bubble-status"> · {statusLabel(message.status)}</span>
            ) : null}
          </div>
          {canRecall ? (
            <button className="bubble-recall" onClick={onRecall} title="撤回">
              撤回
            </button>
          ) : null}
        </>
      )}
    </div>
  );
}

// 媒体内容:图片自动下载解密后内联预览;其它文件显示为下载按钮(按需解密)。
function MediaContent({ media }: { media: MediaDescriptor }) {
  const isImage = media.content_type.startsWith("image/");
  const [imgUrl, setImgUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!isImage) return;
    let url: string | null = null;
    let cancelled = false;
    setErr(null);
    loadMedia(media)
      .then((bytes) => {
        if (cancelled) return;
        url = URL.createObjectURL(new Blob([bytes], { type: media.content_type }));
        setImgUrl(url);
      })
      .catch((e) => {
        if (!cancelled) setErr(errorMessage(e));
      });
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [media, isImage]);

  const onDownload = async () => {
    setBusy(true);
    setErr(null);
    try {
      const bytes = await loadMedia(media);
      const url = URL.createObjectURL(new Blob([bytes], { type: media.content_type }));
      const a = document.createElement("a");
      a.href = url;
      a.download = media.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  if (isImage) {
    if (err) return <div className="media-error">图片加载失败:{err}</div>;
    if (!imgUrl) return <div className="media-loading">正在解密图片…</div>;
    return <img className="media-img" src={imgUrl} alt={media.filename} />;
  }

  return (
    <button className="media-file" onClick={() => void onDownload()} disabled={busy} title="下载并解密">
      <FileText size={20} aria-hidden className="media-file-icon" />
      <span className="media-file-meta">
        <span className="media-file-name">{media.filename}</span>
        <span className="media-file-size">{formatSize(media.size)}</span>
      </span>
      {busy ? <span className="media-file-action">解密中…</span> : <Download size={16} aria-hidden className="media-file-action" />}
      {err ? <span className="media-error">{err}</span> : null}
    </button>
  );
}

function SafetyNumberModal({ peerId, onClose }: { peerId: string; onClose: () => void }) {
  const { getSafetyNumber } = useChat();
  const [number, setNumber] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // 只在打开/切换对端时计算一次(getSafetyNumber 每次渲染都是新函数,不能作为依赖)
  useEffect(() => {
    getSafetyNumber(peerId)
      .then(setNumber)
      .catch((e) => setErr(errorMessage(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peerId]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>安全号码</h3>
          <button className="icon-button" onClick={onClose} aria-label="关闭">
            <X size={18} aria-hidden />
          </button>
        </div>
        <p className="modal-desc">
          当面或通过其它可信渠道核对此号码,双方一致即可确认没有中间人。号码由双方的经典(Ed25519/X25519)与后量子(ML-DSA-65)身份公钥共同决定。
        </p>
        {err ? <div className="new-chat-error">{err}</div> : null}
        {number ? <div className="safety-number mono">{number}</div> : !err ? <div className="chat-center">计算中…</div> : null}
      </div>
    </div>
  );
}

function statusLabel(status: MessageStatus): string {
  switch (status) {
    case "sending":
      return "发送中";
    case "sent":
      return "已发送";
    case "delivered":
      return "已送达";
    case "read":
      return "已读";
    case "failed":
      return "失败";
  }
}
