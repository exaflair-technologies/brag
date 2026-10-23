const CSP =
  "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; media-src 'self' data:; base-uri 'none'";

const SCRIPT_RE = /<script\b[\s\S]*?<\/script\s*>/gi;
const PRELOAD_LINK_RE = /<link\b[^>]*\brel\s*=\s*["']?(?:preload|prefetch|preconnect|dns-prefetch|modulepreload)\b[^>]*>/gi;
const ATTR_RE = /(\s)(src|href|poster|data-src|srcset|data-srcset)(\s*=\s*)("([^"]*)"|'([^']*)')/gi;
const CSS_URL_RE = /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi;
const HEAD_RE = /<head\b[^>]*>/i;
const NO_REWRITE_RE = /^(data:|blob:|#|javascript:|mailto:|about:)/i;
const STYLESHEET_REL_RE = /\brel\s*=\s*["']?[^"'>]*\bstylesheet\b/i;
const NAMED_ENTITIES = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' };

const decodeAttribute = (value) => value.replace(/&(amp|quot|apos|lt|gt);/gi, (_, name) => NAMED_ENTITIES[name.toLowerCase()]);

function isStylesheetLinkAt(html, offset) {
  const start = html.lastIndexOf('<', offset);
  const end = html.indexOf('>', offset);
  return /^<link\b/i.test(html.slice(start, start + 5)) && STYLESHEET_REL_RE.test(html.slice(start, end));
}

function resolveUrl(raw, base) {
  const value = raw.trim();
  if (!value || NO_REWRITE_RE.test(value)) return null;
  try {
    const absolute = new URL(value, base);
    absolute.hash = '';
    return absolute.href;
  } catch {
    return null;
  }
}

export function rewriteCss(css, cssUrl, assets, unresolved = new Set()) {
  return css.replace(CSS_URL_RE, (match, quote, raw) => {
    const absolute = resolveUrl(raw, cssUrl);
    if (!absolute) return match;
    const local = assets.get(absolute);
    if (local) return `url(${quote}${local}${quote})`;
    unresolved.add(absolute);
    return match;
  });
}

export function rewriteDocument(html, pageUrl, assets) {
  const unresolved = new Set();
  const localize = (raw) => {
    const absolute = resolveUrl(decodeAttribute(raw), pageUrl);
    if (!absolute) return null;
    if (assets.has(absolute)) return `assets/${assets.get(absolute)}`;
    return { unresolved: absolute };
  };

  let out = html.replace(SCRIPT_RE, '').replace(PRELOAD_LINK_RE, '');

  out = out.replace(ATTR_RE, (match, space, name, equals, quoted, dq, sq, offset, whole) => {
    const value = dq ?? sq;
    const quote = quoted[0];
    if (name.endsWith('srcset')) {
      const rewritten = value
        .split(',')
        .map((candidate) => {
          const [url, ...descriptor] = candidate.trim().split(/\s+/);
          const result = localize(url);
          const replacement = typeof result === 'string' ? result : url;
          if (result && typeof result !== 'string') unresolved.add(result.unresolved);
          return [replacement, ...descriptor].join(' ');
        })
        .join(', ');
      return `${space}${name}${equals}${quote}${rewritten}${quote}`;
    }
    const result = localize(value);
    if (typeof result === 'string') {
      return `${space}${name}${equals}${quote}${result}${quote}`;
    }
    if (result && (name !== 'href' || isStylesheetLinkAt(whole, offset))) unresolved.add(result.unresolved);
    return match;
  });

  out = out.replace(CSS_URL_RE, (match, quote, raw) => {
    const result = localize(raw);
    if (typeof result === 'string') return `url(${quote}${result}${quote})`;
    if (result) unresolved.add(result.unresolved);
    return match;
  });

  const meta = `<meta http-equiv="Content-Security-Policy" content="${CSP}">`;
  out = HEAD_RE.test(out) ? out.replace(HEAD_RE, (head) => `${head}${meta}`) : `${meta}${out}`;

  return { html: out, unresolved: [...unresolved] };
}
