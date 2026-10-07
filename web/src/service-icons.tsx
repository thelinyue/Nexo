import { useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Search, Trash2 } from "./icons";
import { Confirm, errorText, useApi } from "./ui";

export type IconUpload = { name: string; file: File } | { name: string; data_url: string };
type SharedIcon = { id: string; name: string; created_at: number };
/** 某些浏览器不会为 WebP 提供 MIME，读取文件头识别格式，避免误拒绝正常图片。 */
async function iconFileType(file: File) {
  const bytes = new Uint8Array(await file.slice(0, 12).arrayBuffer());
  if ([137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => bytes[index] === byte)) return "image/png";
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return "image/jpeg";
  if (String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" && String.fromCharCode(...bytes.slice(8, 12)) === "WEBP") return "image/webp";
  throw new Error("请选择 PNG、JPG 或 WebP 图片");
}
export async function readIconUpload(upload: IconUpload): Promise<{ name: string; data_url: string }> {
  if ("data_url" in upload) return upload;
  const mime = await iconFileType(upload.file);
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve({ name: upload.name, data_url: String(reader.result).replace(/^data:[^,]*,/, `data:${mime};base64,`) });
    reader.onerror = () => reject(new Error("无法读取图片，请重新选择"));
    reader.readAsDataURL(upload.file);
  });
}

const styles = [["border-radius", "圆角"], ["circle", "圆形"], ["svg", "SVG"]] as const;
const iconName = (id: string) => id.split("/").pop()!.replace(/\.[^.]+$/, "");
const iconUrl = (id: string) => id.startsWith("upload/") ? `/api/v1/service-icons/${encodeURIComponent(id.slice(7))}/image` : `https://cdn.jsdelivr.net/gh/xushier/HD-Icons@main/${id.split("/").map(encodeURIComponent).join("/")}`;

/** 四枚居中的应用方块作为所有协议的通用标识；内联 SVG 保证离线可用，尺寸由容器等比缩放。 */
function DefaultServiceIcon() {
  return <svg viewBox="0 0 64 64" width="64" height="64" fill="#FFF6E9" aria-hidden="true" focusable="false">
    <rect x="16" y="16" width="14" height="14" rx="3" />
    <rect x="34" y="16" width="14" height="14" rx="3" />
    <rect x="16" y="34" width="14" height="14" rx="3" />
    <rect x="34" y="34" width="14" height="14" rx="3" />
  </svg>;
}

/** 图标加载不阻塞服务操作；图片失败时保留固定尺寸，并回退本地默认图标。 */
export function ServiceIcon({ id, preview }: { id?: string | null; protocol: string; preview?: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [id, preview]);
  const custom = Boolean(preview || id) && !failed;
  return <span className={`application-icon${custom ? "" : " application-icon-default"}`} aria-hidden="true">{custom
    ? <img src={preview || iconUrl(id!)} alt="" loading="lazy" decoding="async" referrerPolicy="no-referrer" onError={() => setFailed(true)} />
    : <DefaultServiceIcon />}</span>;
}

/** 选择器只在展开时加载完整目录。候选仅作推荐，不自动修改草稿或发出写入请求。 */
export function ServiceIconPicker({ value, name, protocol, preview, admin, csrf, onChange, onUpload, onProcessing }: { value: string; name: string; protocol: string; preview?: string; admin?: boolean; csrf?: string | null; onChange: (value: string) => void; onUpload: (upload: IconUpload) => void; onProcessing: (busy: boolean) => void }) {
  const request = useApi();
  const [open, setOpen] = useState(false);
  const [catalog, setCatalog] = useState<string[] | null>(null);
  const [error, setError] = useState(false);
  const [style, setStyle] = useState("border-radius");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [source, setSource] = useState("catalog");
  const [shared, setShared] = useState<SharedIcon[] | null>(null);
  const [sharedError, setSharedError] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  const [processing, setProcessing] = useState(false);
  const [deleting, setDeleting] = useState<SharedIcon | null>(null);
  const sequence = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);
  const id = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const search = useRef<HTMLInputElement>(null);
  async function load() {
    setError(false);
    try { setCatalog((await import("./data/hd-icons.json")).default); }
    catch { setError(true); }
  }
  useEffect(() => { if (open && !catalog) void load(); }, [open]);
  useEffect(() => { if (open) search.current?.focus({ preventScroll: true }); }, [open]);
  useEffect(() => () => { sequence.current++; onProcessing(false); }, []);
  async function loadShared() {
    setSharedError(null);
    try { setShared(await request<SharedIcon[]>("/api/v1/service-icons")); }
    catch (error) { setSharedError(errorText(error)); }
  }
  useEffect(() => { if (open && source === "shared") void loadShared(); }, [open, source]);
  const results = useMemo(() => {
    const words = name.toLowerCase().match(/[a-z0-9]+/g)?.filter(word => word.length > 1) ?? [];
    const aliases = [["飞牛", "fnos"], ["群晖", "synology"], ["威联通", "qnap"], ["极空间", "zspace"], ["绿联", "ugreen"]];
    for (const [label, word] of aliases) if (name.includes(label)) words.push(word);
    const recommend = (id: string) => words.some(word => iconName(id).includes(word));
    return (catalog ?? []).filter(id => id.startsWith(`${style}/`) && iconName(id).includes(query.trim().toLowerCase()))
      .sort((a, b) => Number(recommend(b)) - Number(recommend(a)) || a.localeCompare(b));
  }, [catalog, style, query, name]);
  const sharedResults = (shared ?? []).filter(icon => icon.name.toLowerCase().includes(query.trim().toLowerCase()));
  useEffect(() => setPage(0), [style, query, name, source]);
  function cancelProcessing() { sequence.current++; setProcessing(false); onProcessing(false); }
  function close() { cancelProcessing(); setOpen(false); trigger.current?.focus({ preventScroll: true }); }
  function choose(id: string) { onChange(id); close(); }
  /** 迟到的文件解码或下载结果不能覆盖用户随后选择的图标；本地预览不会发出上传请求。 */
  async function selectFile(file?: File) {
    if (!file) return;
    const seq = ++sequence.current; setUploadError(null); setProcessing(true); onProcessing(true);
    let objectUrl: string | undefined;
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error("图片不能超过 2 MB");
      await iconFileType(file);
      objectUrl = URL.createObjectURL(file);
      const image = new Image();
      await new Promise<void>((resolve, reject) => { image.onload = () => resolve(); image.onerror = () => reject(new Error("图片损坏或无法读取")); image.src = objectUrl!; });
      if (image.naturalWidth > 4096 || image.naturalHeight > 4096) throw new Error("图片尺寸不能超过 4096 × 4096 像素");
      if (seq === sequence.current) { onUpload({ name: file.name, file }); close(); }
    } catch (error) { if (seq === sequence.current) setUploadError(errorText(error)); }
    finally { if (objectUrl) URL.revokeObjectURL(objectUrl); if (seq === sequence.current) { setProcessing(false); onProcessing(false); } }
  }
  async function importLink() {
    const seq = ++sequence.current; setUploadError(null); setProcessing(true); onProcessing(true);
    try {
      const upload = await request<{name: string; data_url: string}>("/api/v1/service-icons/preview", { method: "POST", body: JSON.stringify({ url: url.trim() }) }, csrf);
      if (seq === sequence.current) { onUpload(upload); close(); }
    } catch (error) { if (seq === sequence.current) setUploadError(errorText(error)); }
    finally { if (seq === sequence.current) { setProcessing(false); onProcessing(false); } }
  }
  return <div className="service-icon-picker">
    <button ref={trigger} type="button" className="service-icon-trigger" aria-label="选择应用图标" aria-expanded={open} aria-controls={id} onClick={() => open ? close() : setOpen(true)}><ServiceIcon id={value} protocol={protocol} preview={preview} /><span>更换图标</span></button>
    {open && <section id={id} className="icon-picker-panel" aria-label="应用图标" onKeyDown={event => { if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(); } }}>
      <div className="icon-picker-heading"><strong>应用图标</strong><button type="button" className="text-button" onClick={() => choose("")}>默认图标</button><button type="button" className="text-button" onClick={close}>收起</button></div>
      <div className="icon-picker-actions"><button type="button" className="secondary-button" onClick={() => fileInput.current?.click()}>上传图片</button><input ref={fileInput} className="sr-only" type="file" aria-label="上传图标图片" accept="image/png,image/jpeg,image/webp" onChange={event => { const file = event.target.files?.[0]; event.target.value = ""; void selectFile(file); }} /><button type="button" className="text-button" onClick={() => { cancelProcessing(); setSource(source === "link" ? "catalog" : "link"); setUploadError(null); }}>输入链接</button></div>
      <p className="helper">支持 PNG、JPG、WebP，最大 2 MB。保存服务后加入共享图标库，所有用户均可使用。</p>
      {uploadError && <p className="form-error" role="alert">{uploadError}</p>}
      {processing && <p className="helper" role="status">{source === "link" ? "正在下载图片…" : "正在读取图片…"}</p>}
      {source === "link" && <div className="icon-link-import"><label className="service-field"><span>图片链接</span><input type="url" value={url} placeholder="https://example.com/icon.png" onChange={event => { cancelProcessing(); setUrl(event.target.value); }} onKeyDown={event => { if (event.key === "Enter") { event.preventDefault(); event.stopPropagation(); if (url.trim() && !processing) void importLink(); } }} /></label><button type="button" className="secondary-button" disabled={processing || !url.trim()} onClick={() => void importLink()}>导入预览</button><p className="helper">{admin ? "内网链接需能从 Server 访问；HTTPS 证书必须有效。" : "支持公网图片链接；内网图片可请管理员导入。"}</p></div>}
      <div className="icon-picker-styles" role="group" aria-label="图标来源">{[["catalog", "HD-Icons"], ["shared", "共享图标"]].map(([key, label]) => <button type="button" key={key} aria-pressed={source === key} onClick={() => { cancelProcessing(); setSource(key); }}>{label}</button>)}</div>
      {source !== "link" && <>
      <label className="search"><Search size={17} /><input ref={search} aria-label="搜索应用图标" placeholder="搜索应用，如 Emby" value={query} onChange={event => setQuery(event.target.value)} /></label>
      {source === "catalog" && <>
      <div className="icon-picker-styles" role="group" aria-label="图标风格">{styles.map(([key, label]) => <button type="button" key={key} aria-pressed={style === key} onClick={() => setStyle(key)}>{label}</button>)}</div>
      {!catalog && !error && <p role="status" className="helper">正在加载图标目录…</p>}
      {error && <p role="alert" className="helper">图标目录加载失败。<button type="button" className="text-button" onClick={() => void load()}>重试</button></p>}
      {catalog && <><p className="helper" role="status">{results.length ? `${results.length} 个图标 · 名称匹配优先` : "没有匹配的图标，试试应用英文名"}</p>
        <div className="icon-picker-grid">{results.slice(page * 24, (page + 1) * 24).map(icon => <button type="button" className="icon-picker-option" key={icon} aria-label={`使用 ${iconName(icon)}`} aria-pressed={value === icon} title={iconName(icon)} onClick={() => choose(icon)}><ServiceIcon id={icon} protocol={protocol} /><span>{iconName(icon)}</span></button>)}</div>
        {results.length > 24 && <div className="icon-picker-pages"><button type="button" className="text-button" disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button><span>{page + 1} / {Math.ceil(results.length / 24)}</span><button type="button" className="text-button" disabled={(page + 1) * 24 >= results.length} onClick={() => setPage(page + 1)}>下一页</button></div>}</>}
      <p className="helper icon-picker-source">图标来自 <a href="https://github.com/xushier/HD-Icons" target="_blank" rel="noopener noreferrer">HD-Icons</a> · <a href="/licenses/HD-Icons.txt" target="_blank" rel="noopener noreferrer">MIT 许可</a></p>
      </>}
      {source === "shared" && <>
        {sharedError ? <p className="form-error" role="alert">{sharedError}<button type="button" className="text-button" onClick={() => void loadShared()}>重试</button></p> : !shared ? <p className="helper" role="status">正在加载共享图标…</p> : <>
          <p className="helper" role="status">{sharedResults.length ? `${sharedResults.length} 个共享图标` : "没有匹配的共享图标，可上传图片或输入链接"}</p>
          <div className="icon-picker-grid">{sharedResults.slice(page * 24, (page + 1) * 24).map(icon => <div className="shared-icon-option" key={icon.id}><button type="button" className="icon-picker-option" aria-label={`使用 ${icon.name}`} aria-pressed={!preview && value === icon.id} onClick={() => choose(icon.id)}><ServiceIcon id={icon.id} protocol={protocol} /><span>{icon.name}</span></button>{admin && <button type="button" className="icon-button danger-text" aria-label={`删除图标 ${icon.name}`} onClick={() => setDeleting(icon)}><Trash2 size={16} /></button>}</div>)}</div>
          {sharedResults.length > 24 && <div className="icon-picker-pages"><button type="button" className="text-button" disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button><span>{page + 1} / {Math.ceil(sharedResults.length / 24)}</span><button type="button" className="text-button" disabled={(page + 1) * 24 >= sharedResults.length} onClick={() => setPage(page + 1)}>下一页</button></div>}
        </>}
      </>}
      </>}
    </section>}
    {deleting && createPortal(<Confirm title={`删除图标 ${deleting.name}？`} description="所有用户将无法再选择此图标。正在被服务使用的图标不能删除。" label="删除图标" onClose={() => setDeleting(null)} onConfirm={async () => { await request(`/api/v1/service-icons/${encodeURIComponent(deleting.id.slice(7))}`, { method: "DELETE" }, csrf); setShared(current => current?.filter(icon => icon.id !== deleting.id) ?? null); setPage(0); if (value === deleting.id) onChange(""); }} />, document.body)}
  </div>;
}
