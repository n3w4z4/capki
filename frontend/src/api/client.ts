export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!res.ok) {
    let message = res.statusText
    try {
      const body = await res.json()
      message = body.detail ?? message
    } catch {
      // response had no JSON body
    }
    throw new ApiError(res.status, message)
  }

  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

async function fetchText(path: string): Promise<string> {
  const res = await fetch(path, { credentials: 'include' })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText)
  }
  return res.text()
}

/**
 * Downloads authenticated content as a file. An `<a download href=...>`
 * pointing straight at the API is unreliable for cookie-authenticated,
 * same-origin HTTPS requests in Chrome (manifests as a "check internet
 * connection" download-manager failure) — fetching the bytes ourselves and
 * saving them as a local blob sidesteps that entirely.
 */
async function downloadFile(path: string, filename: string): Promise<void> {
  const res = await fetch(path, { credentials: 'include' })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export const apiClient = {
  get: <T>(path: string) => request<T>(path),
  getText: (path: string) => fetchText(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  download: downloadFile,
}
