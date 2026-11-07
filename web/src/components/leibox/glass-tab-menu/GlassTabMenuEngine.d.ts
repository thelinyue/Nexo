export type GlassTabMenuOptions = { selectedIndex: number | null; enabled: boolean };
export type GlassTabMenuController = { update(options: GlassTabMenuOptions): void; destroy(): void };
export function mountGlassTabMenu(target: HTMLElement, elements: { popover: HTMLElement; trigger: HTMLElement }): GlassTabMenuController;
