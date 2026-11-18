import { useState } from "react";
import type { RelayNode } from "./nodes";
import { Confirm, Modal, Notice, errorText, useApi, useResource } from "./ui";

export type NodeGroup = { id: string; name: string; node_ids: string[]; workspace_ids?: string[]; selectable?: boolean };
type WorkspaceUser = { workspace_id: string; workspace_name: string; enabled: boolean };

/** 用空间名称选择分配对象；组的节点与分配名单一次保存，避免界面形成半成品授权。 */
export function WorkspaceChoices({ value, onChange }: { value: string[]; onChange: (ids: string[]) => void }) {
  const api = useApi(); const users = useResource(() => api<WorkspaceUser[]>("/api/v1/admin/users"), true, false);
  return <fieldset className="node-choice-list"><legend>分配工作空间</legend><Notice error={users.error} onRetry={() => void users.reload()} />{users.data?.map(user => <label className="node-check" key={user.workspace_id}><input type="checkbox" checked={value.includes(user.workspace_id)} disabled={!user.enabled && !value.includes(user.workspace_id)} onChange={e => onChange(e.target.checked ? [...value, user.workspace_id] : value.filter(id => id !== user.workspace_id))} /><span>{user.workspace_name}{!user.enabled && <small>已停用</small>}</span></label>)}</fieldset>;
}

/** 首次直接建组，已有分组先展示列表；成员与分配一次提交，删除仍需明确确认。 */
export function NodeGroupsDialog({ groups, nodes, csrf, onClose }: { groups: NodeGroup[]; nodes: RelayNode[]; csrf?: string | null; onClose: () => void }) {
  const api = useApi(); const [editing, setEditing] = useState<NodeGroup | null>(null); const [creating, setCreating] = useState(groups.length === 0);
  const [name, setName] = useState(""); const [ids, setIds] = useState<string[]>([]); const [workspaces, setWorkspaces] = useState<string[]>([]);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [deleting, setDeleting] = useState<NodeGroup | null>(null);
  const form = creating || editing;
  function edit(group?: NodeGroup) { setEditing(group ?? null); setCreating(!group); setName(group?.name ?? ""); setIds(group?.node_ids ?? []); setWorkspaces(group?.workspace_ids ?? []); setError(null); }
  async function save() {
    setBusy(true); setError(null);
    try { await api(`/api/v1/node-groups${editing ? `/${encodeURIComponent(editing.id)}` : ""}`, { method: editing ? "PUT" : "POST", body: JSON.stringify({ name, node_ids: ids, workspace_ids: workspaces }) }, csrf); onClose(); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <><Modal className="node-modal" title={form ? editing ? "编辑节点组" : "创建节点组" : "节点组"} onClose={onClose} busy={busy} dirty={!!form && (name !== (editing?.name ?? "") || JSON.stringify(ids) !== JSON.stringify(editing?.node_ids ?? []) || JSON.stringify(workspaces) !== JSON.stringify(editing?.workspace_ids ?? []))}>
    {form ? <form className="modal-form" onSubmit={e => { e.preventDefault(); void save(); }}>
      <div className="modal-body node-group-form">
        <label>名称<input required maxLength={80} value={name} onChange={e => setName(e.target.value)} placeholder="例如：亚洲入口" /></label>
        <fieldset className="node-choice-list"><legend>节点（2–16 个） · 已选 {ids.length}</legend>{nodes.filter(node => node.approved).map(node => <label className="node-check" key={node.id}><input type="checkbox" checked={ids.includes(node.id)} onChange={e => setIds(e.target.checked ? [...ids, node.id] : ids.filter(id => id !== node.id))} /><span>{node.name}<small>{node.public_ipv4 || "本地节点"}</small></span></label>)}{nodes.filter(node => node.approved).length < 2 && <p className="helper">需先接入并批准至少两个节点。</p>}</fieldset>
        <WorkspaceChoices value={workspaces} onChange={setWorkspaces} />
        {!workspaces.length && <p className="helper">分配工作空间后，服务才能选择此组。</p>}
        {editing && <p className="helper">成员变更会同步到关联服务。</p>}
        <Notice error={error} />
      </div>
      <footer className="modal-actions">
        {editing && <button type="button" className="text-button danger-text" disabled={busy} onClick={() => setDeleting(editing)}>删除</button>}
        <button className="primary-button" disabled={busy || !name.trim() || ids.length < 2 || ids.length > 16}>{busy ? "处理中…" : editing ? "保存" : "创建"}</button>
      </footer>
    </form> : <><div className="modal-body"><ul className="node-group-list">{groups.map(group => <li key={group.id}><div><strong>{group.name}</strong><small>{group.node_ids.length} 个节点 · {group.workspace_ids?.length ?? 0} 个工作空间</small></div><button className="text-button" onClick={() => edit(group)}>编辑</button><button className="text-button danger-text" aria-label={`删除${group.name}`} onClick={() => setDeleting(group)}>删除</button></li>)}</ul></div><footer className="modal-actions"><button className="primary-button" onClick={() => edit()}>创建节点组</button></footer></>}
  </Modal>
    {deleting && <Confirm title="删除节点组" label="确认删除" description={`删除「${deleting.name}」会解除所有工作空间的服务绑定，并撤销该组授予的权限。服务可继续使用另有授权的原节点，失去全部节点的服务将停用。VPS 和服务配置会保留。`} onClose={() => setDeleting(null)} onConfirm={async () => {
      await api(`/api/v1/node-groups/${encodeURIComponent(deleting.id)}`, { method: "DELETE" }, csrf);
      onClose();
    }} />}
  </>;
}
