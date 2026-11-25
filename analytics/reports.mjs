export function duration(ms) {
  if (ms === null || ms === undefined) return '—';
  const seconds = Math.floor(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

export function csv(rows) {
  return rows.map(row => row.map(value => {
    let field = String(value ?? '');
    if (/^[\t\r\n]|^\s*[=+@\-]/u.test(field)) field = "'" + field;
    return '"' + field.replaceAll('"', '""') + '"';
  }).join(',')).join('\r\n') + '\r\n';
}
