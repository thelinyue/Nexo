/*!
 * Adapted from LeiBox glass-tab-menu (React), https://leibox.pantoria.cn/docs/animations/glass-tab-menu
 * Design reference: solutionb, https://x.com/SolutionB2u/status/2113575003341881728/video/1
 * Source notices and adaptation details: NOTICE.md. No blanket license is assigned by the catalog.
 */

/** 复用原组件的可重定向弹簧，只移动装饰层，不接管原生导航、焦点或 Popover 开关。 */
export function mountGlassTabMenu(target, { popover, trigger }) {
  const indicator = target.querySelector(".bottom-nav-indicator");
  const media = matchMedia("(prefers-reduced-motion: reduce)");
  const position = { p: 0, v: 0, target: 0 };
  const width = { p: 0, v: 0, target: 0 };
  const opening = { p: 0, v: 0, target: 0 };
  let selectedIndex = null, enabled = false, initialized = false, destroyed = false;
  let frame = 0, last = 0, originPending = false;

  function draw() {
    indicator.style.transform = `translateX(${position.p}px)`;
    indicator.style.width = `${width.p}px`;
    indicator.style.opacity = selectedIndex === null ? "0" : "1";
    const progress = Math.min(1, Math.max(0, opening.p));
    popover.style.setProperty("--glass-menu-opacity", String(progress));
    popover.style.setProperty("--glass-menu-offset", `${10 * (1 - progress)}px`);
    popover.style.setProperty("--glass-menu-scale", String(.94 + .06 * progress));
  }
  function measure() {
    const item = target.querySelectorAll(":scope > a,:scope > button")[selectedIndex];
    if (!item || !item.offsetWidth) return;
    position.target = item.offsetLeft;
    width.target = item.offsetWidth;
    if (!initialized) {
      position.p = position.target; width.p = width.target; initialized = true;
    }
  }
  function measureOrigin() {
    // 不把当前缩放后的矩形当作原点；临时读取未变换布局后立即还原，不产生中间帧。
    const transform = popover.style.transform;
    popover.style.transform = "none";
    const box = popover.getBoundingClientRect(), source = trigger.getBoundingClientRect();
    popover.style.transform = transform;
    popover.style.transformOrigin = `${source.x + source.width / 2 - box.x}px ${source.y + source.height / 2 - box.y}px`;
  }
  function settle() {
    cancelAnimationFrame(frame); frame = 0; last = 0;
    for (const state of [position, width, opening]) { state.p = state.target; state.v = 0; }
    draw(); target.dataset.moving = "false"; popover.dataset.moving = "false";
  }
  function step(state, h) {
    // 临界阻尼替代演示中的回弹和延迟；重定向时保留当前位置与速度。
    state.v += ((state.target - state.p) * 400 - state.v * 40) * h;
    state.p += state.v * h;
    if (Math.abs(state.p - state.target) < .01 && Math.abs(state.v) < .02) { state.p = state.target; state.v = 0; }
    return state.p !== state.target || state.v !== 0;
  }
  function tick(time) {
    frame = 0;
    if (destroyed) return;
    if (originPending) { originPending = false; measureOrigin(); }
    if (!enabled || media.matches || document.hidden) { settle(); return; }
    const dt = Math.min(.032, (time - (last || time - 16)) / 1000); last = time;
    let moving = false, menuMoving = false;
    for (let i = 0; i < 3; i++) {
      moving = step(position, dt / 3) || moving;
      moving = step(width, dt / 3) || moving;
      menuMoving = step(opening, dt / 3) || menuMoving;
    }
    draw(); target.dataset.moving = String(moving || menuMoving); popover.dataset.moving = String(menuMoving);
    if (moving || menuMoving) frame = requestAnimationFrame(tick); else last = 0;
  }
  function wake() {
    if (destroyed) return;
    if (!enabled || media.matches || document.hidden) { settle(); return; }
    const menuMoving = opening.p !== opening.target || opening.v !== 0;
    target.dataset.moving = String(menuMoving || position.p !== position.target || width.p !== width.target || position.v !== 0 || width.v !== 0);
    popover.dataset.moving = String(menuMoving);
    if (!frame) frame = requestAnimationFrame(tick);
  }
  function beforeToggle(event) {
    opening.target = Number(event.newState === "open");
    // 原生关闭立即退出交互和读屏顺序，离散退出绘制不能挡住后续点击或 Tab。
    popover.inert = !opening.target;
    originPending = Boolean(opening.target);
    wake();
  }
  function resize() {
    measure();
    if (popover.matches(":popover-open")) measureOrigin();
    settle();
  }
  function preference() { if (media.matches || document.hidden) settle(); }
  // 添加入口由页面投递，挂载时会改变底栏可用宽度；这是重定向，不是跨断点重置。
  // 尺寸通知期间回写指示器会使 WebKit 在同一轮再次布局，延至下一帧合并处理。
  let measureFrame = 0;
  const observer = new ResizeObserver(() => {
    cancelAnimationFrame(measureFrame);
    measureFrame = requestAnimationFrame(() => { measure(); wake(); });
  });
  observer.observe(target);
  popover.addEventListener("beforetoggle", beforeToggle);
  media.addEventListener("change", preference);
  document.addEventListener("visibilitychange", preference);
  window.addEventListener("resize", resize);
  target.dataset.moving = "false"; popover.dataset.moving = "false"; popover.inert = !popover.matches(":popover-open");
  return {
    update(options) {
      if (destroyed) return;
      const first = !enabled;
      enabled = options.enabled; selectedIndex = options.selectedIndex;
      measure();
      if (first) settle(); else wake();
    },
    destroy() {
      destroyed = true; cancelAnimationFrame(frame); cancelAnimationFrame(measureFrame); observer.disconnect();
      popover.removeEventListener("beforetoggle", beforeToggle);
      media.removeEventListener("change", preference);
      document.removeEventListener("visibilitychange", preference);
      window.removeEventListener("resize", resize);
      for (const name of ["--glass-menu-opacity", "--glass-menu-offset", "--glass-menu-scale", "transform-origin"]) popover.style.removeProperty(name);
      indicator.style.removeProperty("transform"); indicator.style.removeProperty("width"); indicator.style.removeProperty("opacity");
      popover.inert = false;
      target.dataset.moving = "false"; popover.dataset.moving = "false";
    },
  };
}
