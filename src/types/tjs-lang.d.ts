/**
 * Type declarations for tjs-lang
 *
 * These mirror the exports from tjs-lang for TypeScript compatibility
 * when the module doesn't have its own declaration files.
 */

declare module 'tjs-lang' {
  export interface Capabilities {
    fetch?: (url: string, init?: any) => Promise<any>
    store?: {
      get: (key: string) => Promise<any>
      set: (key: string, value: any) => Promise<void>
      query?: (query: any) => Promise<any[]>
      vectorSearch?: (
        collection: string,
        vector: number[],
        k?: number,
        filter?: any
      ) => Promise<any[]>
    }
    llm?: {
      predict: (prompt: string, options?: any) => Promise<string>
      embed?: (text: string) => Promise<number[]>
    }
    agent?: {
      run: (agentId: string, input: any) => Promise<any>
    }
    shell?: {
      run: (command: string) => Promise<{ stdout: string; stderr: string; exitCode: number }>
      exec: (binary: string, args?: string[]) => Promise<{ stdout: string; stderr: string; exitCode: number }>
    }
    files?: {
      read: (path: string) => Promise<string>
      write: (path: string, content: string) => Promise<void>
      exists: (path: string) => Promise<boolean>
      list: (path: string) => Promise<string[]>
      stat: (path: string) => Promise<{ size: number; isDirectory: boolean; isFile: boolean; mtime: number }>
      delete: (path: string) => Promise<void>
      mkdir: (path: string) => Promise<void>
    }
    xml?: {
      parse: (xml: string) => Promise<any>
    }
    code?: {
      transpile: (source: string) => { op: string; steps: any[] }
    }
    [key: string]: any
  }

  export interface RunResult {
    result: any
    error?: Error
    fuelUsed: number
    trace?: any[]
    warnings?: string[]
  }

  export interface Atom<I, O> {
    op: string
    docs?: string
    inputSchema?: any
    outputSchema?: any
    exec: (input: I, ctx: RuntimeContext) => Promise<O>
  }

  export interface RuntimeContext {
    fuel: { current: number }
    args: Record<string, any>
    state: Record<string, any>
    consts: Set<string>
    capabilities: Capabilities
    resolver: (op: string) => Atom<any, any> | undefined
    output?: any
    error?: Error
    signal?: AbortSignal
    trace?: any[]
    costOverrides?: Record<string, any>
    context?: Record<string, any>
    warnings?: string[]
  }

  export interface BaseNode {
    op: string
    [key: string]: any
  }

  export type AgentAST = BaseNode

  export interface TranspileResult {
    ast: AgentAST
    source?: string
  }

  export class AgentVM<M extends Record<string, Atom<any, any>> = {}> {
    readonly atoms: any
    constructor(customAtoms?: M)
    get builder(): any
    get Agent(): any
    resolve(op: string): Atom<any, any> | undefined
    getTools(filter?: 'flow' | 'all' | string[]): any[]
    run(
      astOrToken: BaseNode | string,
      args?: Record<string, any>,
      options?: {
        fuel?: number
        capabilities?: Capabilities
        trace?: boolean
        timeoutMs?: number
        signal?: AbortSignal
        costOverrides?: Record<string, any>
        context?: Record<string, any>
      }
    ): Promise<RunResult>
  }

  export function ajs(strings: TemplateStringsArray, ...values: any[]): AgentAST

  export function transpile(source: string): TranspileResult

  export const coreAtoms: Record<string, Atom<any, any>>

  export function defineAtom<I, O>(
    opCode: string,
    inputSchema: any,
    outputSchema: any,
    exec: (step: I, ctx: RuntimeContext) => Promise<void>,
    options?: {
      docs?: string
      timeoutMs?: number
      cost?: number | ((input: I, ctx: RuntimeContext) => number)
    }
  ): Atom<I, O>
}

declare module 'tjs-lang/eval' {
  export interface EvalOptions {
    code: string
    fuel?: number
    capabilities?: import('tjs-lang').Capabilities
  }

  export interface EvalResult {
    result: any
    fuelUsed: number
    error?: Error
  }

  export function Eval(options: EvalOptions): Promise<EvalResult>

  export interface SafeFunctionOptions {
    body: string
    params?: string[]
    fuel?: number
  }

  export function SafeFunction(options: SafeFunctionOptions): Promise<((...args: any[]) => Promise<EvalResult>)>
}
