const crypto = require('crypto')
const Koa = require('koa')
const bodyParser = require('koa-bodyparser')
const test = require('ava')
const request = require('supertest')

const { cryptoMiddleware } = require('../dist/index')

/**
 * Disable console
 */
console.log = console.debug = console.info = console.error = () => ''

const secret = () =>
  '43c8fd6074379f2e6d09a847bf7e72a8ff755b0f1559872bad2185a217b8ca6f'
const app = new Koa()

app.use(bodyParser())
app.use(cryptoMiddleware({ secret }))
app.use((ctx) => {
  ctx.body = 'success'
})

test('should respond 500 with SECRET_INVALID due to invalid secret', async (t) => {
  const localApp = new Koa()

  localApp.silent = true

  localApp.use(
    cryptoMiddleware({
      secret: () => '',
    })
  )

  const response = await request(localApp.listen()).get(`/`).expect(500)

  t.is(response.serverError, true)
})

test('should respond 200 with options request', async (t) => {
  const response = await request(app.listen()).options('/').expect(200)

  t.is(response.text, 'success')
})

test('should respond 200 without cipher text in query', async (t) => {
  const response = await request(app.listen()).get('/').expect(200)

  t.is(response.text, 'success')
})

test('should respond 400 with invalid cipher text in query', async (t) => {
  const response = await request(app.listen()).get('/?cipherText=1').expect(400)

  t.is(response.error.text, 'Unexpected cipher text')
})

test('should respond 400 with outdated cipher text in query', async (t) => {
  const cipherText = encodeURIComponent(
    'mMiCdjFIsUn9UcCw1+VY9q7Ay4AnMOB9KYjqZtNiaKUfzH8Q8nJRLosLH08m7hadsngzaOVnuPEdog35+uQZ0kOZWAdwiGMiNoRuU6dV6BM96IjMd5PU66knhbv0GViP'
  )

  const response = await request(app.listen())
    .get(`/?cipherText=${cipherText}`)
    .expect(400)

  t.is(response.error.text, 'Outdated request')
})

test('should respond 200 with valid cipher text in query', async (t) => {
  const cipherText = encodeURIComponent(
    'mMiCdjFIsUn9UcCw1+VY9hy6r9mZyfNW6RLKvo4e7nU+Chj5a50qw2Omm1qCkge4EBYLeh26tuEAVAHTEaUPo/SSNSiqfhClluBrmErLQZ8='
  )

  const response = await request(app.listen())
    .get(`/?cipherText=${cipherText}`)
    .expect(200)

  t.is(response.text, 'success')
})

test('should respond 200 without cipher text in body', async (t) => {
  const response = await request(app.listen()).post('/').expect(200)

  t.is(response.text, 'success')
})

test('should respond 400 with invalid cipher text in body', async (t) => {
  const response = await request(app.listen())
    .post('/')
    .send({
      cipherText: '1',
    })
    .expect(400)

  t.is(response.error.text, 'Unexpected cipher text')
})

test('should respond 400 with outdated cipher text in body', async (t) => {
  const cipherText =
    'mMiCdjFIsUn9UcCw1+VY9q7Ay4AnMOB9KYjqZtNiaKUfzH8Q8nJRLosLH08m7hadsngzaOVnuPEdog35+uQZ0kOZWAdwiGMiNoRuU6dV6BM96IjMd5PU66knhbv0GViP'

  const response = await request(app.listen())
    .post('/')
    .send({
      cipherText,
    })
    .expect(400)

  t.is(response.error.text, 'Outdated request')
})

test('should respond 200 with valid cipher text in body', async (t) => {
  const cipherText =
    'mMiCdjFIsUn9UcCw1+VY9hy6r9mZyfNW6RLKvo4e7nU+Chj5a50qw2Omm1qCkge4EBYLeh26tuEAVAHTEaUPo/SSNSiqfhClluBrmErLQZ8='

  const response = await request(app.listen())
    .post('/')
    .send({
      cipherText,
    })
    .expect(200)

  t.is(response.text, 'success')
})
