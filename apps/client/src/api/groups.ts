import { apiRequest } from "./client";

export interface Group {
  id: string;
  name: string;
  owner_id: string;
  avatar_url: string;
  created_at: string;
  member_count: number;
}

export interface GroupMember {
  id: string;
  nickname: string;
  avatar_url: string;
  role: string;
}

export interface GroupDetail extends Group {
  members: GroupMember[];
}

export const createGroup = (name: string, memberIds: string[]): Promise<Group> =>
  apiRequest("/api/v1/groups", { method: "POST", auth: true, body: { name, member_ids: memberIds } });

export const listGroups = (): Promise<{ groups: Group[] }> =>
  apiRequest("/api/v1/groups", { auth: true });

export const getGroup = (id: string): Promise<GroupDetail> =>
  apiRequest(`/api/v1/groups/${id}`, { auth: true });

export const addGroupMember = (id: string, userId: string): Promise<unknown> =>
  apiRequest(`/api/v1/groups/${id}/members`, { method: "POST", auth: true, body: { user_id: userId } });

export const removeGroupMember = (id: string, userId: string): Promise<unknown> =>
  apiRequest(`/api/v1/groups/${id}/members/${userId}`, { method: "DELETE", auth: true });

export const leaveGroup = (id: string): Promise<unknown> =>
  apiRequest(`/api/v1/groups/${id}/leave`, { method: "POST", auth: true });
