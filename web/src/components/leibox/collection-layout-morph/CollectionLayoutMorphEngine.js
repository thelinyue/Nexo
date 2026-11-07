/*!
 * Adapted from LeiBox collection-layout-morph (React), https://leibox.pantoria.cn/docs/animations/collection-layout-morph
 * Design reference: Previous Leon, https://x.com/shawn_kel/status/2087937950424129978/video/1
 * Source and removed demo asset notices: NOTICE.md. Original layout/code license was not supplied or independently verified.
 * GSAP is subject to its Standard License: https://gsap.com/standard-license/
 */
import { gsap } from "gsap";
import { Flip } from "gsap/Flip";

gsap.registerPlugin(Flip);

/** 固定三项坐标改为真实 DOM 的 FLIP；只在用户切换视图时动画，轮询和筛选不自动重排。 */
export function mountCollectionLayoutMorph(target) {
  const media = matchMedia("(prefers-reduced-motion: reduce)");
  let view = target.dataset.view, active = false, content, rows = [], captured = null, context = null, destroyed = false;
  let width = target.getBoundingClientRect().width;
  const units = () => [...target.querySelectorAll(":scope > .service-row")];
  const canAnimate = () => active && !media.matches && !document.hidden && !target.querySelector(".copy-fallback");

  function stop() {
    const previous = context; context = null;
    previous?.revert();
    target.dataset.moving = "false";
  }
  function reset() { captured = null; stop(); }
  function changed(next) { return rows.length !== next.length || rows.some((row, index) => row !== next[index]); }
  function capture() {
    captured = null;
    if (!canAnimate() || destroyed) { stop(); return; }
    // 大列表只动画当前视口中的单元，不让屏外条目跨越整页飞入；原节点仍参与正常 CSS 排布。
    const visible = units().filter(row => { const rect = row.getBoundingClientRect(); return rect.bottom > 0 && rect.top < innerHeight; });
    const icons = visible.map(row => row.querySelector(".application-launch"));
    const names = visible.map(row => row.querySelector(".service-identity"));
    // kill:false 先保存当前呈现值，再回收旧时间线；快速反向切换不会先跳到旧终点。
    const snapshot = { icons: Flip.getState(icons, { kill: false }), names: Flip.getState(names, { kill: false }), height: target.getBoundingClientRect().height };
    stop(); captured = snapshot;
  }
  function animate(snapshot) {
    const height = target.getBoundingClientRect().height;
    target.dataset.moving = "true";
    context = gsap.context(() => {
      const timeline = gsap.timeline({ onComplete: stop });
      timeline.add(Flip.from(snapshot.icons, { scale: true, duration: .4, ease: "power2.out", nested: true }), 0);
      // 名称只移动和调整排布尺寸，不随图标一起拉伸文字。
      timeline.add(Flip.from(snapshot.names, { scale: false, duration: .4, ease: "power2.out" }), 0);
      timeline.fromTo(target, { height: snapshot.height }, { height, duration: .4, ease: "power2.out" }, 0);
      const metadata = target.querySelectorAll(".service-list-heading,.service-device,.service-entry,.service-modes,.service-row > .status,.application-status");
      if (metadata.length) timeline.fromTo(metadata, { opacity: 0 }, { opacity: 1, duration: .2 }, .08);
    }, target);
  }
  const observer = new ResizeObserver(() => {
    // 两种视图的边框不同，只比较外部宽度，不能把去掉边框误判为窗口缩放。
    const next = target.getBoundingClientRect().width;
    if (next !== width) { width = next; reset(); }
  });
  observer.observe(target);
  const preference = () => { if (media.matches || document.hidden) reset(); };
  window.addEventListener("resize", reset);
  document.addEventListener("visibilitychange", preference);
  media.addEventListener("change", preference);
  target.dataset.motionComponent = "collection-layout-morph"; target.dataset.moving = "false";
  return {
    capture,
    update(options) {
      if (destroyed) return;
      const next = units();
      if (!options.active || changed(next) || content !== options.content) reset();
      rows = next; active = options.active; content = options.content;
      if (view !== options.view) {
        view = options.view;
        const snapshot = captured; captured = null;
        if (snapshot && canAnimate()) animate(snapshot); else stop();
      }
    },
    destroy() {
      destroyed = true; reset(); observer.disconnect();
      window.removeEventListener("resize", reset);
      document.removeEventListener("visibilitychange", preference);
      media.removeEventListener("change", preference);
    },
  };
}
