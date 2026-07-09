import React, { ReactNode } from 'react'

type Method = 'GET' | 'POST' | 'PATCH' | 'DELETE' | 'gRPC'

type Props = {
  method: Method
  endpoint: string
  /** mutating RPC → returns operation.Operation (long-running async). */
  async?: boolean
  children: ReactNode
}

/**
 * ApiOperation — заголовок-обертка одной RPC-операции: HTTP-метод + REST-путь +
 * бейдж «async · Operation» для мутаций (все Create/Update/Delete возвращают LRO).
 */
export function ApiOperation({ method, endpoint, async: isAsync, children }: Props): React.ReactElement {
  const cls = method.toLowerCase() === 'grpc' ? 'grpc' : method.toLowerCase()
  return (
    <div className="api-op">
      <div className="api-op__head">
        <span className={`api-op__method api-op__method--${cls}`}>{method}</span>
        <span className="api-op__endpoint">{endpoint}</span>
        {isAsync ? <span className="api-op__async">async · Operation</span> : null}
      </div>
      {children}
    </div>
  )
}
