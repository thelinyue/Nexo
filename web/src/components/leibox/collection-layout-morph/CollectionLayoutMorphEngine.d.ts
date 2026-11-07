export type CollectionLayoutMorphController = {
  capture(): void;
  update(options: { view: "list" | "icons"; active: boolean; content: readonly unknown[] | undefined }): void;
  destroy(): void;
};
export function mountCollectionLayoutMorph(target: HTMLElement): CollectionLayoutMorphController;
