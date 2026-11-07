import { useCallback, useLayoutEffect, useRef } from "react";
import { mountCollectionLayoutMorph } from "./CollectionLayoutMorphEngine.js";
import type { CollectionLayoutMorphController } from "./CollectionLayoutMorphEngine.js";

/** 只测量和变换已存在的服务单元，保持长按、多选、复制控件及其 DOM 身份。 */
export function useCollectionLayoutMorph(view: "list" | "icons", active: boolean, content: readonly unknown[] | undefined) {
  const controller = useRef<CollectionLayoutMorphController | null>(null);
  const ref = useCallback((element: HTMLElement | null) => {
    controller.current?.destroy();
    controller.current = element ? mountCollectionLayoutMorph(element) : null;
  }, []);
  // 数据到达后才出现列表，回调 ref 负责挂载；每次提交同步活动状态及轮询后的节点变化。
  useLayoutEffect(() => { controller.current?.update({ view, active, content }); });
  const capture = useCallback(() => controller.current?.capture(), []);
  return { ref, capture };
}
