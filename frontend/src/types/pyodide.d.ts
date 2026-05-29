export interface PyodideInterface {
  runPythonAsync:          (code: string) => Promise<unknown>
  loadPackagesFromImports: (code: string) => Promise<void>
  loadPackage:             (pkgs: string[]) => Promise<void>
  globals:                 { set: (k: string, v: unknown) => void }
}

declare global {
  interface Window {
    loadPyodide?: (cfg: { indexURL: string }) => Promise<PyodideInterface>
  }
}
