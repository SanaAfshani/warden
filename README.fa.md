<div align="center">

# warden

**کنترل‌های امنیتی به شکل decorator — برای سرورهای Fetch-API و مرورگر.**

[![ci](https://github.com/SanaAfshani/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/SanaAfshani/warden/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A522.12-brightgreen.svg)](#پیش‌نیازها)

[English](README.md) · [فارسی](README.fa.md)

</div>

---

<div dir="rtl">

core هر track را نصب می‌کنید به‌علاوهٔ فقط پلاگین‌هایی که لازم دارید. هیچ‌چیز
به‌صورت سراسری پیکربندی نمی‌شود، هیچ‌چیز متغیر محیطی نمی‌خواند، و هیچ کنترلی
اجرا نمی‌شود مگر اینکه خودتان در زنجیره بگذاریدش.

</div>

```bash
# سرور
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-headers @sanaafshani/warden-ssr-authn

# مرورگر
npm i @sanaafshani/warden-csr @sanaafshani/warden-csr-storage

# قوانینی که APIهای ناامن را از کدتان بیرون نگه می‌دارند
npm i -D @sanaafshani/warden-csr-eslint-plugin
```

```ts
export const POST = chain()
  .use(secureHeaders())
  .use(limiter.limit({ scope: 'posts', limit: 30, windowSeconds: 60 }))
  .use(session.required())
  .use(access.require('post:create'))
  .use(body(PostSchema))
  .handle(async (_request, { principal, body }) =>
    Response.json(await createPost(principal.id, body)),
  );
```

<div dir="rtl">

`principal` و `body` روی آن context وجود دارند چون decoratorهای بالاتر
اضافه‌شان کرده‌اند. اگر `session.required()` را بردارید، خط بعدی دیگر کامپایل
نمی‌شود و خطا دقیقاً اسم کلید غایب را می‌گوید.

---

## چرا decorator

لایهٔ امنیتی معمولاً به شکل middleware می‌آید: یک فهرست در فایل پیکربندی، دور
از مسیری که محافظت می‌کند، که فریم‌ورکی اعمالش می‌کند که حالا به آن وابسته‌اید.
از روی خود route نمی‌شود فهمید چه چیزی ازش محافظت می‌کند، ترتیب سراسری است، و
جواب «این endpoint محدودیت نرخ دارد؟» از خواندن دو فایل و حدس زدن درمی‌آید.

اینجا هر کنترل شیئی است که یک handler را می‌پیچد و همان شکل را برمی‌گرداند.
این سه چیز را می‌خرد که فهرست middleware نمی‌تواند:

- **ترتیب همان تودرتویی است، و محلی است.** زنجیره کنار خود handler نوشته
  می‌شود. آنچه از این route محافظت می‌کند همان است که می‌بینید.
- **سیستم تایپ، context را حمل می‌کند.** هر decorator اعلام می‌کند چه لازم
  دارد و چه اضافه می‌کند. درخواست بررسی دسترسی بدون احراز هویت بالای سرش
  خطای کامپایل است، نه پیجر ساعت سه بامداد.
- **بدون فریم‌ورک.** یک زنجیره تابعی است با امضای
  `(Request) => Promise<Response>`. روی route handlerهای Next.js، Hono، Bun،
  Deno، Workers و Node اجرا می‌شود، چون تنها چیزی که استفاده می‌کند همین امضاست.

## دو track

</div>

| Track | Core | اجرا روی | پلاگین‌ها |
| --- | --- | --- | --- |
| **SSR** | `@sanaafshani/warden-ssr` | هر سرور Fetch-API | `headers` `ratelimit` `authn` `csrf` `access` `validate` `logging` `crypto` `ssrf` `upload` |
| **CSR** | `@sanaafshani/warden-csr` | مرورگر | `storage` `sanitize` `access` `sso` `eslint-plugin` |

<div dir="rtl">

هر دو core **صفر وابستگی** دارند و خودشان هیچ کنترلی ندارند — آن‌ها قرارداد
هستند و هر کنترل، پلاگینی است که روی قرارداد ساخته شده.

دو track هیچ کدی به اشتراک نمی‌گذارند. پلاگین SSR هرگز کد مرورگر را
نمی‌کشد و برعکس؛ یک قانون lint در همین مخزن اگر یکی دیگری را import کند build
را می‌اندازد. نام هر پکیج با track خودش شروع می‌شود، پس `npm ls '@sanaafshani/warden-ssr*'`
دقیقاً نشان می‌دهد سرور چه نصب کرده است.

### ترکیب در مرورگر

</div>

```ts
const store = decorate(
  webStorage('local'),
  namespaced('app'),              // بیرونی‌ترین: پیشوند کلید
  expiring({ ttlSeconds: 3600 }), // مهلت داخل متن رمزشده می‌رود
  encrypted({ keyring }),
);
```

<div dir="rtl">

هرچه **داخل** `encrypted` باشد همان است که رمز می‌شود. چون `expiring` بیرون
آن است، مهلت جزئی از متن رمزشده است و قابل دستکاری نیست.

## پلاگین lint

کتابخانه می‌تواند کار امن را آسان کند. نمی‌تواند کار ناامن را ناممکن کند —
`localStorage.setItem` و `dangerouslySetInnerHTML` هنوز یک خط آن‌طرف‌ترند و
کوتاه‌ترند.

پنج قانون این شکاف را می‌بندند و هرکدام **درجهٔ اهمیت** خودش را اعلام می‌کند:

</div>

| درجه | قوانین | یعنی |
| --- | --- | --- |
| **`required`** | `no-dangerous-html`, `no-dom-html-sink`, `require-safe-url` | از کلاسی از تزریق محافظت می‌کند که هیچ‌چیز دیگری در زمان اجرا پوششش نمی‌دهد |
| `recommended` | `no-raw-web-storage`, `no-unsafe-target-blank` | دفاع در عمق — تا حادثه شود به خرابی دومی نیاز دارد |

```js
export default warden.enforce(            // بیرونی‌ترین: فقط چیزی را می‌بیند که بهش داده شود
  { ...warden.configs.recommended, files: ['src/**/*.ts'] },

  warden.waive({
    rule: 'no-dangerous-html',
    files: ['src/components/SafeHtml.tsx'],
    reason: 'تنها sink؛ DOMPurify یک خط بالاترش اجرا می‌شود.',
  }),
);
```

<div dir="rtl">

ESLint از نظر فنی به پلاگین اجازه نمی‌دهد جلوی override را بگیرد — flat config
یک آرایه است و آخرین عضو برنده است. پس `enforce()` خودِ پیکربندی را می‌خواند و
پیکربندی‌ای که قانون `required` را پایین بیاورد **رد می‌کند**، به‌جای اینکه
بی‌صدا دوباره روشنش کند و شما را دنبال این بفرستد که چرا `'off'`تان اثری نداشت.
`waive()` راه فرار نیست؛ فهرست قیمت است: یک scope و یک جمله، هر دو قابل grep و
هر دو داخل diff.

## مستندات

</div>

| | |
| --- | --- |
| [docs/getting-started.md](docs/getting-started.md) | نصب، اولین زنجیره، اولین store |
| [docs/ssr.md](docs/ssr.md) | قرارداد سرور، ترتیب پیشنهادی، نوشتن پلاگین |
| [docs/csr.md](docs/csr.md) | قرارداد مرورگر، ترکیب، نوشتن پلاگین |
| [packages/csr/eslint-plugin](packages/csr/eslint-plugin#readme) | پنج قانون، درجه‌ها، `enforce` و `waive` |
| [SECURITY.md](SECURITY.md) | گزارش آسیب‌پذیری، و آنچه این کتابخانه پوشش نمی‌دهد |

<div dir="rtl">

هر پکیج README خودش را دارد با استدلال پشت کنترلی که ارائه می‌دهد.

## چه کارهایی را انجام نمی‌دهد

صریح نوشته می‌شود تا کسی پوشش را فرض نکند: MFA، جریان بازنشانی رمز، پایگاه
داده، WAF، TLS، اتصال به secrets manager و پیکربندی هشدار، همگی خارج از دامنه‌اند.

هیچ‌چیز در track مرورگر مرز اعتماد نیست. روی ماشینی اجرا می‌شود که کاربر
کنترلش می‌کند: `access` تصمیم می‌گیرد UI چه نشان دهد، نه اینکه چه چیزی مجاز
است، و هر دسترسی باید دوباره توسط سرور بررسی شود.

## پیش‌نیازها

Node **۲۲.۱۲ یا بالاتر** (نسخهٔ ۲۰ به پایان پشتیبانی رسیده، و `require(esm)`
همان چیزی است که به مصرف‌کننده‌های CJS اجازه می‌دهد این پکیج‌ها را بارگذاری
کنند). TypeScript اختیاری است، ولی بیشترِ ارزش این کتابخانه در تایپ‌هایش است.

## ساختار مخزن

</div>

```
packages/ssr/<core|plugin>   track سرور
packages/csr/<core|plugin>   track مرورگر (قوانین lint یک پلاگین CSR است)
docs/                        یک سند برای هر track
tests/                       بررسی‌های انتشار: نسخه‌ها، بازهٔ peerها، LICENSE
```

```bash
npm ci
npm run build       # tsc -b، هر پکیج با tsconfig خودش
npm run typecheck   # سورس و تست‌ها، resolve به src (نیازی به build نیست)
npm run lint        # نیاز به build دارد: ESLint پلاگین را از dist می‌خواند
npm test            # SSR در Node، CSR در jsdom
npm run release     # build تمیز، همهٔ بررسی‌های بالا، سپس npm publish --workspaces
```

<div dir="rtl">

`src` هر پکیج از طریق export condition به نام `@sanaafshani/source` در دسترس
است، که TypeScript (با `customConditions`) و Vitest از آن استفاده می‌کنند؛ پس
تست و typecheck هرگز روی خروجی `dist` کهنه اجرا نمی‌شوند. مصرف‌کنندهٔ منتشرشده
هرگز این condition را نمی‌بیند.

## مشارکت

هر دو سند track با چک‌لیست «نوشتن پلاگین» تمام می‌شوند، که نسخهٔ کوتاه سبک
پروژه است: به‌جای خواندن محیط، option بگیرید؛ state در سطح ماژول نگه ندارید؛
fail closed باشید؛ و از طریق `emit(options.onEvent, …)` گزارش بدهید.

هر تغییر باید `npm run lint`، `npm run typecheck` و `npm test` را سبز نگه دارد.
قانون lint جدید بدون انتخاب درجهٔ اهمیت اصلاً کامپایل نمی‌شود.

## مجوز

[MIT](LICENSE) © ثنا افشانی

</div>
