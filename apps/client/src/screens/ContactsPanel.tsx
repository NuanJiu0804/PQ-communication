import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { UserPlus, MessageSquare, Trash2, Ban, Check, X, RotateCcw } from "lucide-react";

import { errorMessage } from "../api/client";
import * as social from "../api/social";
import type { FriendRequest, Profile } from "../api/social";
import { useChat } from "../chat/ChatContext";
import { Button } from "../components/Button";
import { TextField } from "../components/TextField";

type Tab = "friends" | "requests" | "blocks";

export function ContactsPanel() {
  const { openChat } = useChat();
  const [tab, setTab] = useState<Tab>("friends");
  const [friends, setFriends] = useState<Profile[]>([]);
  const [incoming, setIncoming] = useState<FriendRequest[]>([]);
  const [blocks, setBlocks] = useState<Profile[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const [f, r, b] = await Promise.all([
        social.listFriends(),
        social.listRequests(),
        social.listBlocks(),
      ]);
      setFriends(f.friends);
      setIncoming(r.incoming);
      setBlocks(b.blocks);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = (fn: () => Promise<unknown>) => async () => {
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const onChat = (id: string) => async () => {
    setError(null);
    try {
      await openChat(id);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="contacts">
      <AddFriend onChanged={refresh} onError={setError} />

      <div className="subtabs" role="tablist">
        <button className={tab === "friends" ? "subtab active" : "subtab"} onClick={() => setTab("friends")}>
          好友 {friends.length}
        </button>
        <button className={tab === "requests" ? "subtab active" : "subtab"} onClick={() => setTab("requests")}>
          申请 {incoming.length > 0 ? `(${incoming.length})` : ""}
        </button>
        <button className={tab === "blocks" ? "subtab active" : "subtab"} onClick={() => setTab("blocks")}>
          黑名单 {blocks.length}
        </button>
      </div>

      {error ? <div className="contacts-error">{error}</div> : null}

      <div className="contacts-list">
        {tab === "friends" &&
          (friends.length === 0 ? (
            <div className="conv-empty">还没有好友,用上面的框添加。</div>
          ) : (
            friends.map((f) => (
              <div key={f.id} className="contact-item">
                <span className="avatar avatar-xs" aria-hidden>
                  {f.nickname.slice(0, 1).toUpperCase()}
                </span>
                <span className="contact-text">
                  <span className="contact-name">{f.nickname}</span>
                  <span className="contact-status">{f.status_text || "—"}</span>
                </span>
                <button className="icon-button-sm" onClick={onChat(f.id)} title="聊天">
                  <MessageSquare size={15} aria-hidden />
                </button>
                <button className="icon-button-sm" onClick={run(() => social.removeFriend(f.id))} title="删除好友">
                  <Trash2 size={15} aria-hidden />
                </button>
                <button className="icon-button-sm" onClick={run(() => social.blockUser(f.id))} title="拉黑">
                  <Ban size={15} aria-hidden />
                </button>
              </div>
            ))
          ))}

        {tab === "requests" &&
          (incoming.length === 0 ? (
            <div className="conv-empty">没有待处理的好友申请。</div>
          ) : (
            incoming.map((r) => (
              <div key={r.id} className="contact-item">
                <span className="avatar avatar-xs" aria-hidden>
                  {r.user.nickname.slice(0, 1).toUpperCase()}
                </span>
                <span className="contact-text">
                  <span className="contact-name">{r.user.nickname}</span>
                  <span className="contact-status">{r.note || "请求添加你为好友"}</span>
                </span>
                <button className="icon-button-sm accept" onClick={run(() => social.acceptRequest(r.id))} title="同意">
                  <Check size={15} aria-hidden />
                </button>
                <button className="icon-button-sm" onClick={run(() => social.rejectRequest(r.id))} title="拒绝">
                  <X size={15} aria-hidden />
                </button>
              </div>
            ))
          ))}

        {tab === "blocks" &&
          (blocks.length === 0 ? (
            <div className="conv-empty">黑名单为空。</div>
          ) : (
            blocks.map((b) => (
              <div key={b.id} className="contact-item">
                <span className="avatar avatar-xs" aria-hidden>
                  {b.nickname.slice(0, 1).toUpperCase()}
                </span>
                <span className="contact-text">
                  <span className="contact-name">{b.nickname}</span>
                  <span className="contact-status mono">{b.id.slice(0, 8)}…</span>
                </span>
                <button className="icon-button-sm" onClick={run(() => social.unblockUser(b.id))} title="移出黑名单">
                  <RotateCcw size={15} aria-hidden />
                </button>
              </div>
            ))
          ))}
      </div>
    </div>
  );
}

function AddFriend({ onChanged, onError }: { onChanged: () => void; onError: (e: string | null) => void }) {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const onAdd = async (e: FormEvent) => {
    e.preventDefault();
    onError(null);
    setNotice(null);
    setBusy(true);
    try {
      let userId = input.trim();
      if (userId.includes("@")) {
        const p = await social.searchByEmail(userId);
        userId = p.id;
      }
      const r = await social.sendFriendRequest(userId, "");
      setNotice(r.auto_accepted ? "已互加为好友" : "好友申请已发送");
      setInput("");
      onChanged();
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="add-friend" onSubmit={onAdd}>
      <TextField
        label="添加好友"
        name="addfriend"
        mono
        placeholder="对方用户 ID 或邮箱"
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />
      {notice ? <div className="add-friend-notice">{notice}</div> : null}
      <Button type="submit" variant="ghost" loading={busy} className="new-chat-btn">
        <UserPlus size={16} aria-hidden /> 添加
      </Button>
    </form>
  );
}
