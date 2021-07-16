import crypto from 'crypto'
import * as Koa from 'koa'
import unless from 'koa-unless'
import _ from 'lodash'

const decrypt = function decrypt(
  secret: string,
  cipherText: string
): Record<string, any> {
  const aesKey = Buffer.from(secret, 'hex')
  const iv = aesKey.slice(0, 16)
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv)

  const plaintext = Buffer.concat([
    decipher.update(cipherText, 'base64'),
    decipher.final(),
  ])

  const result = JSON.parse(plaintext.toString('utf8'))

  return result
}

const outdated = function outdated(timestamp: number, min = 5): boolean {
  const now = Date.now()
  const diff = Math.abs(now - timestamp)
  const m = 60000 // 60 * 1000
  const minutes = diff / m

  return minutes > min
}

interface CryptoMiddlewareOptions {
  secret: (ctx: Koa.Context) => string | Promise<string>
}

export function cryptoMiddleware(
  options: CryptoMiddlewareOptions
): Koa.Middleware {
  const middleware = async function middleware(
    ctx: Koa.Context,
    next: Koa.Next
  ): Promise<any> {
    const { method, query } = ctx
    const logger = ctx.logger || console
    const { body } = ctx.request

    if (method === 'OPTIONS') {
      return next()
    }

    const secret: string = await options.secret(ctx)

    if (!secret) {
      ctx.throw(500, 'Invalid secret', {
        code: 'SECRET_INVALID',
      })
    }

    const hasQuery = !_.isEmpty(query)
    const hasBody = !_.isEmpty(body)

    if (method === 'GET' || method === 'DELETE' || hasQuery) {
      const cipherText: string = query ? query.cipherText : ''

      if (cipherText) {
        let plaintext: Record<string, any> = {}

        try {
          plaintext = decrypt(secret, cipherText)
        } catch (err) {
          logger.error(
            `cannot decrypt cipher text: ${cipherText}, Error: ${err.message}`
          )

          ctx.throw(400, 'Unexpected cipher text', {
            code: 'CIPHER_TEXT_UNEXPECTED',
          })
        }

        logger.info(
          'Decrypt cipher text of the params in request. Plaintext: %o',
          plaintext
        )

        if (plaintext.timestamp) {
          const isOutdated = outdated(plaintext.timestamp)

          if (isOutdated) {
            ctx.throw(400, 'Outdated request', {
              code: 'REQUEST_OUTDATED',
            })
          }
        }

        ctx.query = _.omit(plaintext, ['timestamp', 'nonce'])
      }
    }

    if (
      method === 'POST' ||
      method === 'PUT' ||
      method === 'PATCH' ||
      hasBody
    ) {
      const cipherText = body ? body.cipherText : ''

      if (cipherText) {
        let plaintext: Record<string, any> = {}

        try {
          plaintext = decrypt(secret, cipherText)
        } catch (err) {
          logger.error(
            `cannot decrypt cipher text: ${cipherText}, Error: ${err.message}`
          )

          ctx.throw(400, 'Unexpected cipher text', {
            code: 'CIPHER_TEXT_UNEXPECTED',
          })
        }

        logger.info(
          'Decrypt cipher text of the body in request. Plaintext: %o',
          plaintext
        )

        if (plaintext.timestamp) {
          const isOutdated = outdated(plaintext.timestamp)

          if (isOutdated) {
            ctx.throw(400, 'Outdated request', {
              code: 'REQUEST_OUTDATED',
            })
          }
        }

        ctx.request.body = _.omit(plaintext, ['timestamp', 'nonce'])
      }
    }

    return next()
  }

  middleware.unless = unless

  return middleware
}
