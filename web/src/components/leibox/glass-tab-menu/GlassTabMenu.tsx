import { useEffect, useRef } from "react";
import type { ReactNode, RefObject } from "react";
import { mountGlassTabMenu } from "./GlassTabMenuEngine.js";
import type { GlassTabMenuController } from "./GlassTabMenuEngine.js";

/** 动画只装饰现有导航；链接、Popover 和权限仍由工作区管理，不另建页签状态。 */
export function GlassTabMenu({ selectedIndex, enabled, popover, trigger, children }: {
  selectedIndex: number | null; enabled: boolean;
  popover: RefObject<HTMLDivElement | null>; trigger: RefObject<HTMLButtonElement | null>; children: ReactNode;
}) {
  const host = useRef<HTMLElement>(null);
  const controller = useRef<GlassTabMenuController | null>(null);
  useEffect(() => {
    if (!enabled) return;
    // 等同级 Popover 完成 ref 挂载后再接入；切到桌面时回收整个动画控制器。
    const instance = mountGlassTabMenu(host.current!, { popover: popover.current!, trigger: trigger.current! });
    controller.current = instance;
    return () => { instance.destroy(); controller.current = null; };
  }, [enabled]);
  useEffect(() => { controller.current?.update({ selectedIndex, enabled }); }, [selectedIndex, enabled]);
  return <nav ref={host} className="bottom-nav" aria-label="底部导航" data-motion-component="glass-tab-menu" data-moving="false">
    <span className="bottom-nav-indicator" aria-hidden="true" />{children}
  </nav>;
}
