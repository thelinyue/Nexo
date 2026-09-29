import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Globe, Network, Search } from "./icons";
import { isPortProtocol } from "./ui";

const styles = [["border-radius", "圆角"], ["circle", "圆形"], ["svg", "SVG"]] as const;
const iconName = (id: string) => id.split("/").pop()!.replace(/\.[^.]+$/, "");
const iconUrl = (id: string) => `https://cdn.jsdelivr.net/gh/xushier/HD-Icons@main/${id.split("/").map(encodeURIComponent).join("/")}`;

/** 图标加载不阻塞服务操作；远程图片失败时保留固定尺寸，并回退协议图标。 */
export function ServiceIcon({ id, protocol }: { id?: string | null; protocol: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [id]);
  const Icon = isPortProtocol(protocol) ? Network : Globe;
  return <span className="application-icon" aria-hidden="true">{id && !failed
    ? <img src={iconUrl(id)} alt="" loading="lazy" decoding="async" referrerPolicy="no-referrer" onError={() => setFailed(true)} />
    : <Icon size={26} />}</span>;
}

/** 选择器只在展开时加载完整目录。候选仅作推荐，不自动修改草稿或发出写入请求。 */
export function ServiceIconPicker({ value, name, protocol, onChange }: { value: string; name: string; protocol: string; onChange: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  const [catalog, setCatalog] = useState<string[] | null>(null);
  const [error, setError] = useState(false);
  const [style, setStyle] = useState("border-radius");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
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
  const results = useMemo(() => {
    const words = name.toLowerCase().match(/[a-z0-9]+/g)?.filter(word => word.length > 1) ?? [];
    const aliases = [["飞牛", "fnos"], ["群晖", "synology"], ["威联通", "qnap"], ["极空间", "zspace"], ["绿联", "ugreen"]];
    for (const [label, word] of aliases) if (name.includes(label)) words.push(word);
    const recommend = (id: string) => words.some(word => iconName(id).includes(word));
    return (catalog ?? []).filter(id => id.startsWith(`${style}/`) && iconName(id).includes(query.trim().toLowerCase()))
      .sort((a, b) => Number(recommend(b)) - Number(recommend(a)) || a.localeCompare(b));
  }, [catalog, style, query, name]);
  useEffect(() => setPage(0), [style, query, name]);
  function close() { setOpen(false); trigger.current?.focus({ preventScroll: true }); }
  function choose(id: string) { onChange(id); close(); }
  return <div className="service-icon-picker">
    <button ref={trigger} type="button" className="service-icon-trigger" aria-label="选择应用图标" aria-expanded={open} aria-controls={id} onClick={() => open ? close() : setOpen(true)}><ServiceIcon id={value} protocol={protocol} /><span>更换图标</span></button>
    {open && <section id={id} className="icon-picker-panel" aria-label="应用图标" onKeyDown={event => { if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(); } }}>
      <div className="icon-picker-heading"><strong>应用图标</strong><button type="button" className="text-button" onClick={() => choose("")}>默认图标</button><button type="button" className="text-button" onClick={close}>收起</button></div>
      <label className="search"><Search size={17} /><input ref={search} aria-label="搜索应用图标" placeholder="搜索应用，如 Emby" value={query} onChange={event => setQuery(event.target.value)} /></label>
      <div className="icon-picker-styles" role="group" aria-label="图标风格">{styles.map(([key, label]) => <button type="button" key={key} aria-pressed={style === key} onClick={() => setStyle(key)}>{label}</button>)}</div>
      {!catalog && !error && <p role="status" className="helper">正在加载图标目录…</p>}
      {error && <p role="alert" className="helper">图标目录加载失败。<button type="button" className="text-button" onClick={() => void load()}>重试</button></p>}
      {catalog && <><p className="helper" role="status">{results.length ? `${results.length} 个图标 · 名称匹配优先` : "没有匹配的图标，试试应用英文名"}</p>
        <div className="icon-picker-grid">{results.slice(page * 24, (page + 1) * 24).map(icon => <button type="button" className="icon-picker-option" key={icon} aria-label={`使用 ${iconName(icon)}`} aria-pressed={value === icon} title={iconName(icon)} onClick={() => choose(icon)}><ServiceIcon id={icon} protocol={protocol} /><span>{iconName(icon)}</span></button>)}</div>
        {results.length > 24 && <div className="icon-picker-pages"><button type="button" className="text-button" disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button><span>{page + 1} / {Math.ceil(results.length / 24)}</span><button type="button" className="text-button" disabled={(page + 1) * 24 >= results.length} onClick={() => setPage(page + 1)}>下一页</button></div>}</>}
      <p className="helper icon-picker-source">图标来自 <a href="https://github.com/xushier/HD-Icons" target="_blank" rel="noopener noreferrer">HD-Icons</a> · <a href="/licenses/HD-Icons.txt" target="_blank" rel="noopener noreferrer">MIT 许可</a></p>
    </section>}
  </div>;
}
