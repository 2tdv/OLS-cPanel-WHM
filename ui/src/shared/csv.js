// CSV export (RFC 4180). Cells that a spreadsheet would read as a formula (=, +, -, @, tab, carriage
// return) are prefixed with an apostrophe: findings quote tenant-controlled .htaccess text.
export function csvCell(value) {
  let text = value === null || value === undefined ? '' : Array.isArray(value) ? value.join(' ') : String(value)
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

/** columns: [{ label, value: row => any }] */
export function toCsv(rows, columns) {
  const lines = [columns.map(c => csvCell(c.label)).join(',')]
  for (const row of rows) lines.push(columns.map(c => csvCell(c.value(row))).join(','))
  return lines.join('\r\n') + '\r\n'
}

export function downloadText(filename, text, type = 'text/csv;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
