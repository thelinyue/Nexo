import { animate } from "motion";
import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { Modal } from "./ui";

/** 应用详情保留原生 dialog 的隔离与键盘行为，仅负责从来源图标展开和可中断的收起。
 * 关闭回调在动画完成后执行；编辑、内部导航也走同一出口，避免叠加两个详情界面。
 */
export function ApplicationModal({ title, header, origin, enterFromOrigin, returnFocus, dismissWhen = false, busy = false, onClose, children }: {
  title: string; header: ReactNode; origin: HTMLElement | null; enterFromOrigin: boolean;
  returnFocus: () => HTMLElement | null; dismissWhen?: boolean; busy?: boolean; onClose: () => void;
  children: (leave: (after?: () => void) => void) => ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const animations = useRef<{ stop: () => void }[]>([]);
  const mounted = useRef(false);
  const closing = useRef(false);
  const viewport = useRef({ width: innerWidth, height: innerHeight });
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  function sourceBox() {
    if (!origin?.isConnected || origin.closest("[hidden]") || viewport.current.width !== innerWidth || viewport.current.height !== innerHeight) return null;
    const box = origin.getBoundingClientRect();
    return box.width && box.top >= 0 && box.left >= 0 && box.bottom <= innerHeight && box.right <= innerWidth ? box : null;
  }
  function stop() { animations.current.forEach(animation => animation.stop()); animations.current = []; }
  function leave(after = onClose) {
    if (closing.current || busy) return;
    closing.current = true;
    stop();
    const panel = dialog.current!;
    panel.dataset.closing = "true";
    const icon = panel.querySelector<HTMLElement>(".application-summary .application-icon");
    const source = !reduced() && sourceBox();
    // 先读取不含动画变换的目标位置，保留当前变换值供 Motion 接续，避免快速关闭时跳回起点。
    if (icon && source) {
      const transform = icon.style.transform;
      icon.style.transform = "none";
      const target = icon.getBoundingClientRect();
      icon.style.transform = transform;
      animations.current.push(animate(icon, { x: source.left - target.left, y: source.top - target.top, scale: source.width / target.width }, { type: "spring", bounce: 0, duration: .3 }));
    }
    const end = animate(panel, { opacity: 0, scale: source ? .97 : 1 }, source ? { type: "spring", bounce: 0, duration: .3 } : { duration: .12 });
    animations.current.push(end);
    void end.then(() => { if (mounted.current) after(); });
  }
  useEffect(() => {
    mounted.current = true;
    const panel = dialog.current!;
    const icon = panel.querySelector<HTMLElement>(".application-summary .application-icon");
    const source = enterFromOrigin && !reduced() && sourceBox();
    if (icon && source) {
      const target = icon.getBoundingClientRect();
      animations.current.push(animate(icon, { x: [source.left - target.left, 0], y: [source.top - target.top, 0], scale: [source.width / target.width, 1] }, { type: "spring", bounce: 0, duration: .3 }));
    }
    animations.current.push(animate(panel, { opacity: [0, 1], scale: [source ? .97 : 1, 1] }, source ? { type: "spring", bounce: 0, duration: .3 } : { duration: .12 }));
    return () => { mounted.current = false; stop(); };
  }, []);
  useEffect(() => { if (dismissWhen) leave(); }, [dismissWhen]);
  return <Modal title={title} header={header} className="application-modal service-detail" dialogRef={dialog} returnFocus={returnFocus} busy={busy} onClose={() => leave()}>{children(leave)}</Modal>;
}
