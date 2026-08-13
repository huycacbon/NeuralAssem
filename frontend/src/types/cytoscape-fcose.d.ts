/**
 * `cytoscape-fcose` ships no type declarations. It is an extension registered
 * via `cytoscape.use()`, so a minimal module declaration is enough - the layout
 * options themselves are typed at the call site in `graphStyle.ts`.
 */
declare module 'cytoscape-fcose' {
  import type cytoscape from 'cytoscape';

  const extension: cytoscape.Ext;
  export default extension;
}
