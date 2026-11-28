// Kasumi production-support plans. This file is the single source of plan
// data: the page renders it, scripts/stripe-setup.mjs creates the Stripe
// Products and Prices from it, and /api/checkout refuses any Stripe Price
// that disagrees with it. After changing prices, run the setup script.
//
// Tier design, response targets and prices follow a Codex (gpt-6.2-astra)
// survey of published database support offerings (MongoDB, Redis,
// CockroachDB, Couchbase, EDB, Percona, Neo4j, ScyllaDB, YugabyteDB, TiDB,
// Elastic, Aiven, and the Japanese vendors SRA OSS, Ashisuto and SmartStyle)
// on 2026-11-27. Prices are tax-exclusive. Annual = 11 × monthly.
//
// Any user-visible string may be a plain string or {en: "...", ja: "..."}.
window.KASUMI_PLANS = {
  // One switch for online sales: false hides the Subscribe buttons AND makes
  // /api/checkout refuse to create Stripe sessions.
  selfServeOpen: true,

  // Bump `revision` whenever prices or tiers change: /api/checkout refuses
  // purchases from pages rendered with an older revision. `termsVersion`
  // names the immutable copy public/legal/support-terms-<termsVersion>.html
  // that Checkout links to and records on each subscription.
  revision: "2026-11-27",
  termsVersion: "2026-11-27",

  currencies: ["JPY", "USD"],
  defaultCurrency: "JPY",
  intervals: ["month", "year"],
  defaultInterval: "year",
  contactEmail: "service@soramitsu.co.jp",
  portalUrl: "", // Stripe customer-portal login link (https://billing.stripe.com/p/login/...)
  stripeTaxCode: "txcd_20060017", // Technical Support Services; confirm with the tax adviser

  // Domestic tax-inclusive amount shown next to tax-exclusive prices.
  taxInclusive: { JPY: { rate: 0.1, label: { en: "{amount} incl. 10% consumption tax (Japan)", ja: "国内税込 {amount}" } } },
  taxNote: {
    en: "Prices exclude tax. Customers in Japan pay 10% consumption tax, calculated at checkout; please choose JPY, so your qualified invoice is issued in yen. USD is for customers outside Japan. All times are JST (UTC+9).",
    ja: "表示価格は税別です。国内のお客様には消費税（10%）を加算し、決済画面で計算します。適格請求書を円建てで発行するため、国内のお客様は日本円をお選びください。米ドル建ては海外のお客様向けです。時刻はすべて日本時間（UTC+9）です。",
  },

  tiers: [
    {
      id: "standard",
      name: "Standard",
      featured: false,
      audience: { en: "One production installation", ja: "本番環境1件の運用に" },
      summary: {
        en: "The engineers who build Kasumi, by ticket, during the Tokyo working day.",
        ja: "Kasumi を開発するエンジニアが、平日日中にチケットで対応します。",
      },
      checkout: true,
      ctaLabel: { en: "Subscribe", ja: "申し込む" },
      price: { JPY: { month: 60000, year: 660000 }, USD: { month: 400, year: 4400 } },
      priceNote: null,
      highlights: [
        { en: "1 production installation and 1 staging installation", ja: "本番環境1件・検証環境1件" },
        { en: "Sev 1 response within 4 business hours", ja: "Sev 1 は営業時間内で通算4時間以内に初回応答" },
        { en: "Email and support portal, in Japanese or English", ja: "メールとサポートポータル（日本語・英語）" },
        { en: "2 named contacts", ja: "指定連絡担当者2名" },
        { en: "Fixes in published maintenance releases", ja: "公開メンテナンスリリースで修正を提供" },
      ],
    },
    {
      id: "business",
      name: "Business",
      featured: true,
      audience: { en: "Customer-facing services, including three-voter clusters", ja: "投票権を持つ3ノードで構成されるクラスタを含む、顧客向けサービスに" },
      summary: {
        en: "Faster response, replicated deployments, incident calls and a planned review every half-year.",
        ja: "より速い初回応答、レプリケーション構成、障害時の通話、半年ごとの設計レビュー。",
      },
      checkout: true,
      ctaLabel: { en: "Subscribe", ja: "申し込む" },
      price: { JPY: { month: 180000, year: 1980000 }, USD: { month: 1200, year: 13200 } },
      priceNote: null,
      highlights: [
        { en: "Up to 2 production installations: embedded, standalone or three-voter", ja: "本番環境最大2件（組み込み・スタンドアロン・3ノードクラスタ）" },
        { en: "Sev 1 response within 2 business hours", ja: "Sev 1 は営業時間内で通算2時間以内に初回応答" },
        { en: "Phone or video bridge during active incidents", ja: "障害対応中は電話・ビデオ会議で対応" },
        { en: "4 named contacts and a named onboarding lead", ja: "指定連絡担当者4名・オンボーディング担当者" },
        { en: "60-minute architecture or upgrade review every half-year", ja: "半年ごとに60分のアーキテクチャ／アップグレードレビュー" },
        { en: "Engineering escalation and backport consideration for Sev 1–2 defects", ja: "Sev 1–2 不具合の開発チームへの引き継ぎとバックポート検討" },
      ],
    },
    {
      id: "enterprise",
      name: "Enterprise",
      featured: false,
      audience: { en: "When an outage needs an engineer outside Japan business hours", ja: "夜間・休日の障害にもエンジニアが必要な運用に" },
      summary: {
        en: "24×7 Sev 1 emergency response, a named technical lead and quarterly reviews. Annual contract.",
        ja: "Sev 1 の24時間365日緊急対応、専任テクニカルリード、四半期レビュー。年間契約です。",
      },
      checkout: false,
      ctaLabel: { en: "Talk to us", ja: "お問い合わせ" },
      price: { JPY: { month: 900000, year: 9900000 }, USD: { month: 6000, year: 66000 } },
      priceFrom: true, // shown as "From ¥…" / "¥…〜"
      priceNote: { en: "Quoted for your installations; signed annual order.", ja: "対象環境に応じて個別見積・年間契約。" },
      highlights: [
        { en: "Up to 4 production installations; larger estates quoted", ja: "本番環境最大4件（それ以上は個別見積）" },
        { en: "Sev 1 response within 1 hour, 24×7, via emergency paging", ja: "Sev 1 は24時間365日、緊急連絡から1時間以内に初回応答" },
        { en: "Shared Slack or Teams channel", ja: "Slack または Teams の共有チャンネル" },
        { en: "8 named contacts; named technical lead and deputy", ja: "指定連絡担当者8名・専任テクニカルリードと副担当" },
        { en: "Quarterly 90-minute review and a yearly upgrade or recovery-drill review", ja: "四半期ごとの90分レビューと年1回のアップグレード／復旧訓練レビュー" },
        { en: "Priority hotfix assessment on your build", ja: "ご利用ビルドへの優先ホットフィックス検討" },
      ],
    },
  ],

  // Before production: a scoped pilot, sold by quote.
  pilot: {
    title: { en: "Design-partner pilot", ja: "デザインパートナー・パイロット" },
    body: {
      en: "Evaluating Kasumi before production? A four-week engagement on a named revision and a non-production workload: an architecture session, a supervised install, one agreed retry or recovery exercise, and a written findings review. Fixed fee after scoping.",
      ja: "本番導入前の評価に。指定リビジョンと非本番ワークロードを対象とした4週間の支援です。アーキテクチャセッション、立ち会いのもとでのインストール、合意したリトライまたは復旧の演習1回、所見をまとめたレビューを行います。スコープ確定後の固定料金です。",
    },
    ctaLabel: { en: "Apply for a pilot", ja: "パイロットを申し込む" },
    subject: { en: "Kasumi design-partner pilot", ja: "Kasumi デザインパートナー・パイロットの申し込み" },
  },

  matrix: [
    {
      group: { en: "Scope", ja: "対象範囲" },
      rows: [
        { label: { en: "Production installations", ja: "本番環境" },
          values: { standard: "1", business: { en: "Up to 2", ja: "最大2件" }, enterprise: { en: "Up to 4, more quoted", ja: "最大4件（追加は見積）" } } },
        { label: { en: "Non-production installations", ja: "非本番環境" },
          values: { standard: { en: "1 staging", ja: "検証環境1件" }, business: { en: "1 staging per production", ja: "本番1件ごとに検証環境1件" }, enterprise: { en: "Staging per production, plus a recovery-drill environment", ja: "本番ごとの検証環境＋復旧訓練環境" } } },
        { label: { en: "Three-voter replicated clusters", ja: "3ノードクラスタ（レプリケーション）" },
          values: { standard: false, business: true, enterprise: true } },
      ],
    },
    {
      group: { en: "Initial response targets", ja: "初回応答目標" },
      rows: [
        { label: "Sev 1", values: { standard: { en: "4 business hours", ja: "営業時間内で通算4時間" }, business: { en: "2 business hours", ja: "営業時間内で通算2時間" }, enterprise: { en: "1 hour, 24×7", ja: "1時間（24時間365日）" } } },
        { label: "Sev 2", values: { standard: { en: "8 business hours", ja: "営業時間内で通算8時間" }, business: { en: "4 business hours", ja: "営業時間内で通算4時間" }, enterprise: { en: "2 business hours", ja: "営業時間内で通算2時間" } } },
        { label: "Sev 3", values: { standard: { en: "2 business days", ja: "2営業日" }, business: { en: "1 business day", ja: "1営業日" }, enterprise: { en: "8 business hours", ja: "営業時間内で通算8時間" } } },
        { label: "Sev 4", values: { standard: { en: "3 business days", ja: "3営業日" }, business: { en: "2 business days", ja: "2営業日" }, enterprise: { en: "1 business day", ja: "1営業日" } } },
        { label: { en: "Coverage", ja: "対応時間" },
          values: { standard: { en: "Mon–Fri 09:00–18:00 JST", ja: "平日 9:00–18:00" }, business: { en: "Mon–Fri 09:00–18:00 JST", ja: "平日 9:00–18:00" }, enterprise: { en: "Business hours, and 24×7 for Sev 1", ja: "平日日中＋Sev 1 は24時間365日" } } },
      ],
    },
    {
      group: { en: "Channels and people", ja: "窓口と体制" },
      rows: [
        { label: { en: "Email and support portal", ja: "メール・サポートポータル" }, values: { standard: true, business: true, enterprise: true } },
        { label: { en: "Phone or video bridge in incidents", ja: "障害時の電話・ビデオ会議" },
          values: { standard: false, business: { en: "Scheduled", ja: "日時を調整して実施" }, enterprise: { en: "Engineer-led, with emergency paging", ja: "エンジニア主導・緊急呼び出しあり" } } },
        { label: { en: "Shared Slack or Teams channel", ja: "Slack／Teams 共有チャンネル" }, values: { standard: false, business: false, enterprise: true } },
        { label: { en: "Named contacts", ja: "指定連絡担当者" }, values: { standard: "2", business: "4", enterprise: "8" } },
        { label: { en: "Named Soramitsu staff", ja: "当社の担当者" },
          values: { standard: false, business: { en: "Onboarding lead", ja: "オンボーディング担当" }, enterprise: { en: "Technical lead and deputy", ja: "テクニカルリードと副担当" } } },
        { label: { en: "Languages", ja: "対応言語" },
          values: { standard: { en: "Japanese, English (written)", ja: "日本語・英語（書面）" }, business: { en: "Japanese, English (written and calls)", ja: "日本語・英語（書面・通話）" }, enterprise: { en: "Japanese, English, incl. emergency intake", ja: "日本語・英語（緊急受付を含む）" } } },
      ],
    },
    {
      group: { en: "Engineering", ja: "技術支援" },
      rows: [
        { label: { en: "Architecture and upgrade reviews", ja: "アーキテクチャ・アップグレードレビュー" },
          values: { standard: { en: "By ticket", ja: "チケットで対応" }, business: { en: "60 min every half-year", ja: "半年ごとに60分" }, enterprise: { en: "90 min quarterly, plus a yearly drill review", ja: "四半期ごとに90分＋年1回の訓練レビュー" } } },
        { label: { en: "Security advisories", ja: "セキュリティアドバイザリ" },
          values: { standard: { en: "Public advisories", ja: "公開アドバイザリ" }, business: { en: "Direct notice at publication", ja: "公開時に直接通知" }, enterprise: { en: "Advance mitigation notice when disclosure permits", ja: "開示条件が許す場合は事前に緩和策を通知" } } },
        { label: { en: "Fixes and backports", ja: "修正とバックポート" },
          values: { standard: { en: "Published maintenance releases", ja: "公開メンテナンスリリース" }, business: { en: "Sev 1–2 escalation; backport considered", ja: "Sev 1–2 の開発チームへの引き継ぎ・バックポート検討" }, enterprise: { en: "Priority hotfix assessment on your build", ja: "ご利用ビルドへの優先ホットフィックス検討" } } },
      ],
    },
    {
      group: { en: "Billing", ja: "契約" },
      rows: [
        { label: { en: "How to buy", ja: "お申し込み" },
          values: { standard: { en: "Online, monthly or annual", ja: "オンライン（月額・年額）" }, business: { en: "Online, monthly or annual", ja: "オンライン（月額・年額）" }, enterprise: { en: "Signed annual order", ja: "年間契約（注文書）" } } },
      ],
    },
  ],

  severities: [
    { level: "Sev 1", name: { en: "Critical", ja: "緊急" },
      description: { en: "A covered production installation cannot serve a critical workload, has lost write quorum, or shows credible ongoing data loss or corruption that needs immediate containment.",
                     ja: "対象の本番環境が重要な処理を提供できない、書き込みクォーラムを失っている、またはデータの消失・破損が進行している可能性が高く、直ちに封じ込めが必要な状態。" } },
    { level: "Sev 2", name: { en: "High", ja: "高" },
      description: { en: "Serious production degradation, loss of redundancy while quorum remains, or a failed recovery capability with material operational risk.",
                     ja: "本番環境の深刻な低下、クォーラムを維持したまま冗長性を失った状態、または重大な運用リスクを伴う復旧手段の障害。" } },
    { level: "Sev 3", name: { en: "Normal", ja: "通常" },
      description: { en: "A non-critical defect, a problem with a usable workaround, or a blocked staging upgrade.",
                     ja: "重大ではない不具合、回避策がある問題、または検証環境でのアップグレードの停止。" } },
    { level: "Sev 4", name: { en: "Low", ja: "低" },
      description: { en: "Usage, documentation or configuration questions, and planned changes.",
                     ja: "使い方・ドキュメント・設定に関する質問、計画的な変更。" } },
  ],
  responseNote: {
    en: "Response targets measure the first engineer response (an assessment, containment advice or a concrete diagnostic request) to a ticket from a registered contact. Business-hour targets count only business hours: a ticket that arrives outside them starts counting at the next business day's opening. Automated receipts don't count. They are not resolution, uptime or time-to-patch guarantees. Business hours exclude Japanese public holidays.",
    ja: "応答目標は、登録された連絡担当者からのチケットに対し、エンジニアが最初に応答する（状況評価、封じ込めの助言、または具体的な診断情報の依頼）までの時間です。営業時間ベースの目標は営業時間のみを数え、営業時間外に届いたチケットは翌営業日の始業時から数えます。自動受付通知は含みません。解決時間・稼働率・修正提供時間の保証ではありません。営業時間には日本の祝日を含みません。",
  },
};
