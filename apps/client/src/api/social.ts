import { apiRequest } from "./client";

export interface Profile {
  id: string;
  nickname: string;
  avatar_url: string;
  status_text: string;
}

export interface FriendRequest {
  id: string;
  user: Profile;
  note: string;
  created_at: string;
}

export const getUser = (userId: string): Promise<Profile> =>
  apiRequest(`/api/v1/users/${userId}`, { auth: true });

export const searchByEmail = (email: string): Promise<Profile> =>
  apiRequest(`/api/v1/search/users?email=${encodeURIComponent(email)}`, { auth: true });

export const updateProfile = (patch: {
  nickname?: string;
  avatar_url?: string;
  status_text?: string;
}): Promise<Profile> => apiRequest("/api/v1/me/profile", { method: "PATCH", auth: true, body: patch });

export const listFriends = (): Promise<{ friends: Profile[] }> =>
  apiRequest("/api/v1/friends", { auth: true });

export const removeFriend = (userId: string): Promise<unknown> =>
  apiRequest(`/api/v1/friends/${userId}`, { method: "DELETE", auth: true });

export const sendFriendRequest = (
  toUserId: string,
  note: string,
): Promise<{ message: string; auto_accepted: boolean }> =>
  apiRequest("/api/v1/friend-requests", {
    method: "POST",
    auth: true,
    body: { to_user_id: toUserId, note },
  });

export const listRequests = (): Promise<{ incoming: FriendRequest[]; outgoing: FriendRequest[] }> =>
  apiRequest("/api/v1/friend-requests", { auth: true });

export const acceptRequest = (id: string): Promise<unknown> =>
  apiRequest(`/api/v1/friend-requests/${id}/accept`, { method: "POST", auth: true });

export const rejectRequest = (id: string): Promise<unknown> =>
  apiRequest(`/api/v1/friend-requests/${id}/reject`, { method: "POST", auth: true });

export const listBlocks = (): Promise<{ blocks: Profile[] }> =>
  apiRequest("/api/v1/blocks", { auth: true });

export const blockUser = (userId: string): Promise<unknown> =>
  apiRequest(`/api/v1/blocks/${userId}`, { method: "POST", auth: true });

export const unblockUser = (userId: string): Promise<unknown> =>
  apiRequest(`/api/v1/blocks/${userId}`, { method: "DELETE", auth: true });
