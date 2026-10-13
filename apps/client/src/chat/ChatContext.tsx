import { createContext, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import { fetchMe } from "../api/auth";
import { ApiError, errorMessage } from "../api/client";
import { fetchBundle, fetchPresence } from "../api/keys";
import { createGroup, getGroup, listGroups } from "../api/groups";
import type { Group, GroupMember } from "../api/groups";
import { createUploadUrl } from "../api/media";
import { getUser } from "../api/social";
import type { Profile } from "../api/social";
import { tokenStore } from "../auth/storage";
import { useAuth } from "../auth/AuthContext";
import {
  cryptoDecrypt,
  cryptoEncrypt,
  cryptoHasSession,
  cryptoSafetyNumber,
  cryptoStartSession,
  isDesktop,
  isNoSessionError,
  mediaEncrypt,
  storeLoadMessages,
  storeSaveMessages,
} from "../crypto/core";
import { syncPrekeys } from "../crypto/prekeys";
import { base64ToBytes, bytesToBase64 } from "../util/bytes";
import { RelayClient } from "./relay";
import type { RelayStatus, WsEnvelope } from "./relay";

export type MessageStatus = "sending" | "sent" | "delivered" | "read" | "failed";

/** 媒体消息描述符:随 E2EE 消息发送(密文存 MinIO,密钥/ nonce 端到端传递)。 */
export interface MediaDescriptor {
  object_key: string;
  key: string;
  nonce: string;
  filename: string;
  content_type: string;
  size: number;
}

/** 媒体消息的明文负载前缀(用于在解密后识别媒体消息)。 */
const MEDIA_PREFIX = "PQMEDIA:";
/** 控制消息前缀:端到端加密传输但不显示(例如会话重建通知)。 */
const CONTROL_PREFIX = "PQCTRL:";
/** 单条文本消息长度上限(字符)。 */
export const MAX_TEXT_LENGTH = 4000;
/** 单个媒体文件大小上限(与 Rust 侧一致)。 */
export const MAX_MEDIA_BYTES = 20 * 1024 * 1024;

export interface ChatMessage {
  id: string;
  serverId?: string;
  dir: "out" | "in";
  text: string;
  at: number;
  status?: MessageStatus;
  recalled?: boolean;
  senderId?: string; // 群消息中用于显示发送者
  media?: MediaDescriptor; // 媒体消息
  system?: boolean; // 本地生成的系统提示(安全号码变化、无法解密等)
}

// 会话键:1:1 用对方 userId;群用 "g:"+groupId。
const groupKey = (groupId: string) => `g:${groupId}`;
const isGroupKey = (k: string) => k.startsWith("g:");
const groupIdOf = (k: string) => k.slice(2);

type Status = "unsupported" | "initializing" | "ready" | "error";

interface ChatValue {
  status: Status;
  error: string | null;
  relayStatus: RelayStatus;
  conversations: Record<string, ChatMessage[]>;
  unread: Record<string, number>;
  typingPeers: Record<string, boolean>;
  presence: Record<string, boolean>;
  groups: Group[];
  groupMembers: Record<string, GroupMember[]>;
  profiles: Record<string, Profile>;
  activePeer: string | null;
  selectPeer: (key: string) => void;
  openChat: (peerId: string) => Promise<void>;
  openGroup: (groupId: string) => Promise<void>;
  createGroupChat: (name: string, memberIds: string[]) => Promise<void>;
  refreshGroups: () => Promise<void>;
  sendMessage: (text: string) => Promise<void>;
  sendMedia: (file: File) => Promise<void>;
  recallMessage: (localId: string) => void;
  notifyTyping: () => void;
  getSafetyNumber: (peerId: string) => Promise<string>;
}

const ChatContext = createContext<ChatValue | undefined>(undefined);

function appendMessage(
  prev: Record<string, ChatMessage[]>,
  key: string,
  msg: ChatMessage,
): Record<string, ChatMessage[]> {
  return { ...prev, [key]: [...(prev[key] ?? []), msg] };
}

function patchMessages(
  prev: Record<string, ChatMessage[]>,
  match: (m: ChatMessage) => boolean,
  patch: Partial<ChatMessage>,
): Record<string, ChatMessage[]> {
  const next: Record<string, ChatMessage[]> = {};
  for (const [key, msgs] of Object.entries(prev)) {
    next[key] = msgs.map((m) => (match(m) ? { ...m, ...patch } : m));
  }
  return next;
}

export function ChatProvider({ children }: { children: ReactNode }) {
  const { user, doLogout } = useAuth();
  const selfId = user?.id ?? "";

  const [status, setStatus] = useState<Status>("initializing");
  const [error, setError] = useState<string | null>(null);
  const [relayStatus, setRelayStatus] = useState<RelayStatus>("disconnected");
  const [conversations, setConversations] = useState<Record<string, ChatMessage[]>>({});
  const [unread, setUnread] = useState<Record<string, number>>({});
  const [typingPeers, setTypingPeers] = useState<Record<string, boolean>>({});
  const [presence, setPresence] = useState<Record<string, boolean>>({});
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupMembers, setGroupMembers] = useState<Record<string, GroupMember[]>>({});

  const [activePeer, setActivePeer] = useState<string | null>(null);
  // 1:1 会话对端的公开资料(昵称),用于列表与会话头展示
  const [profiles, setProfiles] = useState<Record<string, Profile>>({});
  const requestedProfiles = useRef<Set<string>>(new Set());

  const relayRef = useRef<RelayClient | null>(null);
  const queueRef = useRef<Promise<void>>(Promise.resolve());
  const activePeerRef = useRef<string | null>(null);
  const groupMembersRef = useRef<Record<string, GroupMember[]>>({});
  const groupsRef = useRef<Group[]>([]);
  const typingTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  const lastTypingSent = useRef(0);
  // 已处理的服务端信封 ID:重连补发或竞态导致的重复投递不得再次解密(消息密钥已用掉)
  const seenEnvelopes = useRef<Set<string>>(new Set());
  // 正在重建会话的对端,避免短时间内重复握手
  const resettingPeers = useRef<Set<string>>(new Set());
  const lastPrekeySync = useRef(0);

  useEffect(() => {
    activePeerRef.current = activePeer;
  }, [activePeer]);
  useEffect(() => {
    groupMembersRef.current = groupMembers;
  }, [groupMembers]);
  useEffect(() => {
    groupsRef.current = groups;
  }, [groups]);

  const markPeerOnline = (peer: string) => setPresence((p) => ({ ...p, [peer]: true }));

  const addSystemNotice = (key: string, text: string) =>
    setConversations((prev) =>
      appendMessage(prev, key, { id: crypto.randomUUID(), dir: "in", text, at: Date.now(), system: true }),
    );

  const identityChangedNotice = (peer: string) =>
    addSystemNotice(peer, "对方的身份密钥已变化(可能重装或重置了客户端)。请点击右上角盾牌,重新核对安全号码。");

  // 确保与某对端有可用会话;没有则领取其预密钥包发起会话。
  const ensureSession = async (peerId: string) => {
    if (await cryptoHasSession(peerId)) return;
    const bundle = await fetchBundle(peerId);
    if (await cryptoStartSession(peerId, bundle)) identityChangedNotice(peerId);
  };

  // 本机没有与对端的会话(例如本机重置过本地数据)却收到其常规消息:
  // 主动重新握手并发送一条控制消息,对端收到后会切换到新会话。
  const renegotiateSession = async (peerId: string) => {
    if (resettingPeers.current.has(peerId)) return;
    resettingPeers.current.add(peerId);
    setTimeout(() => resettingPeers.current.delete(peerId), 30_000);
    try {
      const bundle = await fetchBundle(peerId);
      if (await cryptoStartSession(peerId, bundle)) identityChangedNotice(peerId);
      const env = await cryptoEncrypt(peerId, `${CONTROL_PREFIX}session-reset`);
      relayRef.current?.send(peerId, env.envelope_type, env.payload, crypto.randomUUID());
    } catch (e) {
      console.warn("重建会话失败", e);
    }
  };

  // 他人每次与本机建立新会话都会消耗一个一次性预密钥;适时补充(节流)。
  const maybeSyncPrekeys = () => {
    const now = Date.now();
    if (now - lastPrekeySync.current < 60_000) return;
    lastPrekeySync.current = now;
    syncPrekeys(false).catch((e) => console.warn("补充预密钥失败", e));
  };

  const handleEnvelope = async (env: WsEnvelope) => {
    switch (env.type) {
      case "ack": {
        if (!env.client_ref) return;
        const status: MessageStatus =
          env.status === "error" ? "failed" : env.status === "delivered" ? "delivered" : "sent";
        setConversations((prev) => patchMessages(prev, (m) => m.id === env.client_ref, { serverId: env.id, status }));
        return;
      }
      case "receipt": {
        if (!env.message_id) return;
        const status: MessageStatus = env.status === "read" ? "read" : "delivered";
        // 已读不应被迟到的「已送达」覆盖回去
        setConversations((prev) =>
          patchMessages(prev, (m) => m.serverId === env.message_id && !(status === "delivered" && m.status === "read"), {
            status,
          }),
        );
        if (env.from) markPeerOnline(env.from);
        return;
      }
      case "typing": {
        if (!env.from) return;
        markPeerOnline(env.from);
        setTypingPeers((p) => ({ ...p, [env.from!]: !!env.typing }));
        if (typingTimers.current[env.from]) clearTimeout(typingTimers.current[env.from]);
        if (env.typing) {
          typingTimers.current[env.from] = setTimeout(() => {
            setTypingPeers((p) => ({ ...p, [env.from!]: false }));
          }, 4000);
        }
        return;
      }
      case "recall": {
        if (!env.message_id || !env.from) return;
        // 只允许撤回「对方发给我、且位于与对方会话中」的消息
        const from = env.from;
        setConversations((prev) => {
          const msgs = prev[from];
          if (!msgs) return prev;
          return {
            ...prev,
            [from]: msgs.map((m) =>
              m.dir === "in" && m.serverId === env.message_id ? { ...m, recalled: true, text: "", media: undefined } : m,
            ),
          };
        });
        return;
      }
      case "message": {
        if (!env.from || !env.payload || !env.envelope_type) return;
        if (env.id) {
          if (seenEnvelopes.current.has(env.id)) return;
          seenEnvelopes.current.add(env.id);
        }
        markPeerOnline(env.from);
        const convKey = env.group_id ? groupKey(env.group_id) : env.from;

        let plain: string;
        try {
          const out = await cryptoDecrypt(env.from, env.envelope_type, env.payload);
          plain = out.plaintext;
          if (out.identity_changed) identityChangedNotice(env.from);
          if (env.envelope_type === "prekey") maybeSyncPrekeys();
        } catch (e) {
          console.error("解密失败", e);
          const noSession = isNoSessionError(e);
          addSystemNotice(
            convKey,
            noSession
              ? "收到一条无法解密的消息(本机没有与对方的加密会话),已自动重新协商会话,请让对方重发。"
              : "收到一条无法解密的消息(可能被篡改或重复投递),已丢弃。",
          );
          if (noSession) void renegotiateSession(env.from);
          return;
        }

        if (plain.startsWith(CONTROL_PREFIX)) return; // 控制消息不展示

        let text = plain;
        let media: MediaDescriptor | undefined;
        if (plain.startsWith(MEDIA_PREFIX)) {
          try {
            media = JSON.parse(plain.slice(MEDIA_PREFIX.length)) as MediaDescriptor;
            text = media.filename;
          } catch {
            // 解析失败按普通文本处理
          }
        }
        const id = env.id ?? crypto.randomUUID();
        setConversations((prev) =>
          appendMessage(prev, convKey, {
            id,
            serverId: env.id,
            dir: "in",
            text,
            media,
            at: env.created_at ?? Date.now(),
            senderId: env.from,
          }),
        );
        if (activePeerRef.current === convKey) {
          // 仅 1:1 会话回已读;群消息不做逐条回执
          if (!env.group_id && env.id) relayRef.current?.sendReadReceipt(env.from, env.id);
        } else {
          setUnread((u) => ({ ...u, [convKey]: (u[convKey] ?? 0) + 1 }));
        }
        // 被他人拉入的新群:刷新群列表,否则群名与群组面板都看不到它
        if (env.group_id && !groupsRef.current.some((g) => g.id === env.group_id)) {
          listGroups()
            .then((r) => setGroups(r.groups))
            .catch(() => undefined);
        }
        // 群消息:缓存成员以便显示发送者昵称
        if (env.group_id && !groupMembersRef.current[env.group_id]) {
          getGroup(env.group_id)
            .then((d) => setGroupMembers((p) => ({ ...p, [env.group_id!]: d.members })))
            .catch(() => undefined);
        }
        return;
      }
    }
  };

  useEffect(() => {
    if (!isDesktop()) {
      setStatus("unsupported");
      return;
    }
    let cancelled = false;
    let relay: RelayClient | null = null;

    // 每次(重)连前取最新的访问令牌:先发一次鉴权请求,令牌过期时会自动用刷新令牌换新。
    const getFreshToken = async (): Promise<string | null> => {
      try {
        await fetchMe();
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {
          // 刷新令牌也已失效(过期/被吊销/账号被封禁):回到登录页
          if (!cancelled) void doLogout();
          return null;
        }
      }
      return tokenStore.getAccess();
    };

    (async () => {
      try {
        setStatus("initializing");
        try {
          const saved = await storeLoadMessages();
          if (saved && !cancelled) {
            const history = JSON.parse(saved) as Record<string, ChatMessage[]>;
            for (const msgs of Object.values(history)) {
              for (const m of msgs) if (m.serverId) seenEnvelopes.current.add(m.serverId);
            }
            setConversations(history);
          }
        } catch {
          // 历史加载失败不阻塞
        }
        if (cancelled) return;
        relay = new RelayClient(
          getFreshToken,
          (env) => {
            queueRef.current = queueRef.current.then(() => handleEnvelope(env)).catch((e) => console.error(e));
          },
          setRelayStatus,
        );
        relayRef.current = relay;
        relay.connect();
        setStatus("ready");
        listGroups()
          .then((r) => setGroups(r.groups))
          .catch(() => undefined);
      } catch (e) {
        if (!cancelled) {
          setStatus("error");
          setError(errorMessage(e));
        }
      }
    })();

    return () => {
      cancelled = true;
      relay?.close();
      relayRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    for (const key of Object.keys(conversations)) {
      if (isGroupKey(key) || requestedProfiles.current.has(key)) continue;
      requestedProfiles.current.add(key);
      getUser(key)
        .then((p) => setProfiles((prev) => ({ ...prev, [key]: p })))
        .catch(() => requestedProfiles.current.delete(key));
    }
  }, [conversations]);

  useEffect(() => {
    if (!isDesktop() || status !== "ready") return;
    const timer = setTimeout(() => {
      storeSaveMessages(JSON.stringify(conversations)).catch(() => undefined);
    }, 500);
    return () => clearTimeout(timer);
  }, [conversations, status]);

  const markRead = (peer: string) => {
    setUnread((u) => ({ ...u, [peer]: 0 }));
    if (isGroupKey(peer)) return; // 群不做逐条已读回执
    for (const m of conversations[peer] ?? []) {
      if (m.dir === "in" && m.serverId && !m.system) {
        relayRef.current?.sendReadReceipt(peer, m.serverId);
      }
    }
  };

  const selectPeer = (key: string) => {
    setActivePeer(key);
    markRead(key);
    if (!isGroupKey(key)) {
      fetchPresence(key)
        .then((p) => setPresence((prev) => ({ ...prev, [key]: p.online })))
        .catch(() => undefined);
    }
  };

  const openChat = async (peerIdRaw: string) => {
    const peerId = peerIdRaw.trim();
    if (!peerId) throw new Error("请输入对方的用户 ID");
    if (peerId === selfId) throw new Error("不能与自己建立会话");

    await ensureSession(peerId);
    setConversations((prev) => (prev[peerId] ? prev : { ...prev, [peerId]: [] }));
    selectPeer(peerId);
  };

  const refreshGroups = async () => {
    const r = await listGroups();
    setGroups(r.groups);
  };

  const openGroup = async (groupId: string) => {
    const detail = await getGroup(groupId);
    setGroupMembers((p) => ({ ...p, [groupId]: detail.members }));
    const key = groupKey(groupId);
    setConversations((prev) => (prev[key] ? prev : { ...prev, [key]: [] }));
    selectPeer(key);
  };

  const createGroupChat = async (name: string, memberIds: string[]) => {
    const g = await createGroup(name, memberIds);
    await refreshGroups();
    await openGroup(g.id);
  };

  // 群消息:成对扇出——对每个成员复用其 1:1 会话各加密一份。
  // 每次发送前都取最新成员列表,避免继续向已退群/被移除的成员发送。
  const sendGroup = async (groupId: string, text: string, ref: string) => {
    const detail = await getGroup(groupId);
    setGroupMembers((p) => ({ ...p, [groupId]: detail.members }));
    let ok = 0;
    let failed = 0;
    for (const m of detail.members) {
      if (m.id === selfId) continue;
      try {
        await ensureSession(m.id);
        const env = await cryptoEncrypt(m.id, text);
        if (relayRef.current?.send(m.id, env.envelope_type, env.payload, `${ref}:${m.id}`, groupId)) ok++;
        else failed++;
      } catch (e) {
        console.warn("群消息扇出失败", m.id, e);
        failed++;
      }
    }
    return { ok, failed };
  };

  // 把明文经会话加密后投递到会话(1:1 或群成对扇出)。
  const deliver = async (conv: string, plaintext: string, ref: string) => {
    if (isGroupKey(conv)) {
      const { ok, failed } = await sendGroup(groupIdOf(conv), plaintext, ref);
      const status: MessageStatus = failed > 0 && ok === 0 ? "failed" : "sent";
      setConversations((prev) => patchMessages(prev, (m) => m.id === ref, { status }));
      if (failed > 0 && ok > 0) addSystemNotice(conv, `有 ${failed} 名成员未能送达(对方可能尚未发布密钥或网络中断)。`);
    } else {
      await ensureSession(conv);
      const env = await cryptoEncrypt(conv, plaintext);
      const ok = relayRef.current?.send(conv, env.envelope_type, env.payload, ref);
      if (!ok) setConversations((prev) => patchMessages(prev, (m) => m.id === ref, { status: "failed" }));
    }
  };

  const sendMessage = async (textRaw: string) => {
    const conv = activePeer;
    const text = textRaw.trim();
    if (!conv || !text) return;
    if (text.length > MAX_TEXT_LENGTH) throw new Error(`消息过长(上限 ${MAX_TEXT_LENGTH} 字)`);

    const ref = crypto.randomUUID();
    setConversations((prev) =>
      appendMessage(prev, conv, { id: ref, dir: "out", text, at: Date.now(), status: "sending", senderId: selfId }),
    );
    try {
      await deliver(conv, text, ref);
    } catch (e) {
      setConversations((prev) => patchMessages(prev, (m) => m.id === ref, { status: "failed" }));
      throw e;
    }
  };

  // 发送媒体:客户端先用一次性密钥加密 → 上传密文到 MinIO → 把描述符(含密钥)随 E2EE 消息发出。
  const sendMedia = async (file: File) => {
    const conv = activePeer;
    if (!conv) return;
    if (file.size > MAX_MEDIA_BYTES) throw new Error(`文件过大(上限 ${MAX_MEDIA_BYTES / 1024 / 1024} MB)`);
    const ref = crypto.randomUUID();
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const sealed = await mediaEncrypt(bytesToBase64(bytes));
      const contentType = file.type || "application/octet-stream";
      const cipherBytes = base64ToBytes(sealed.ciphertext);
      const up = await createUploadUrl(contentType, cipherBytes.length);
      const putRes = await fetch(up.upload_url, { method: "PUT", body: cipherBytes });
      if (!putRes.ok) throw new Error("媒体上传失败");
      const descriptor: MediaDescriptor = {
        object_key: up.object_key,
        key: sealed.key,
        nonce: sealed.nonce,
        filename: file.name,
        content_type: contentType,
        size: file.size,
      };
      setConversations((prev) =>
        appendMessage(prev, conv, {
          id: ref,
          dir: "out",
          text: file.name,
          media: descriptor,
          at: Date.now(),
          status: "sending",
          senderId: selfId,
        }),
      );
      await deliver(conv, MEDIA_PREFIX + JSON.stringify(descriptor), ref);
    } catch (e) {
      setConversations((prev) => patchMessages(prev, (m) => m.id === ref, { status: "failed" }));
      throw e;
    }
  };

  const recallMessage = (localId: string) => {
    const peer = activePeer;
    if (!peer || isGroupKey(peer)) return; // 群消息暂不支持撤回
    const msg = (conversations[peer] ?? []).find((m) => m.id === localId);
    if (!msg || msg.dir !== "out" || !msg.serverId) return;
    if (!relayRef.current?.sendRecall(peer, msg.serverId)) return; // 未连接:不在本地假装已撤回
    setConversations((prev) =>
      patchMessages(prev, (m) => m.id === localId, { recalled: true, text: "", media: undefined }),
    );
  };

  const notifyTyping = () => {
    const peer = activePeer;
    if (!peer || isGroupKey(peer)) return;
    const now = Date.now();
    if (now - lastTypingSent.current > 1500) {
      lastTypingSent.current = now;
      relayRef.current?.sendTyping(peer, true);
    }
  };

  const getSafetyNumber = (peerId: string) => cryptoSafetyNumber(peerId);

  return (
    <ChatContext.Provider
      value={{
        status,
        error,
        relayStatus,
        conversations,
        unread,
        typingPeers,
        presence,
        groups,
        groupMembers,
        profiles,
        activePeer,
        selectPeer,
        openChat,
        openGroup,
        createGroupChat,
        refreshGroups,
        sendMessage,
        sendMedia,
        recallMessage,
        notifyTyping,
        getSafetyNumber,
      }}
    >
      {children}
    </ChatContext.Provider>
  );
}

export function useChat(): ChatValue {
  const ctx = useContext(ChatContext);
  if (!ctx) {
    throw new Error("useChat 必须在 ChatProvider 内使用");
  }
  return ctx;
}
