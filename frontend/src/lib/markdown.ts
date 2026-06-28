// Tiny, dependency-free Markdown → HTML renderer for backend-generated trusted
// report content. Handles headings, bold/italic/code, lists, tables, hr and
// paragraphs. Input is HTML-escaped first so the output is safe to inject.

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function inline(s: string): string {
  return escapeHtml(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
}

export function renderMarkdown(md: string): string {
  if (!md) return "";
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const out: string[] = [];
  let i = 0;

  const closeList = (stack: string[]) => {
    while (stack.length) out.push(`</${stack.pop()}>`);
  };
  const listStack: string[] = [];

  while (i < lines.length) {
    const line = lines[i];

    // Tables: a header row followed by a separator row of dashes/pipes.
    if (/\|/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:-]*\|[\s:|-]*$/.test(lines[i + 1])) {
      closeList(listStack);
      const headerCells = line.split("|").map((c) => c.trim());
      // Trim leading/trailing empty cells from pipe edges
      if (headerCells[0] === "") headerCells.shift();
      if (headerCells[headerCells.length - 1] === "") headerCells.pop();
      i += 2; // skip header + separator
      const rows: string[][] = [];
      while (i < lines.length && /\|/.test(lines[i])) {
        const cells = lines[i].split("|").map((c) => c.trim());
        if (cells[0] === "") cells.shift();
        if (cells[cells.length - 1] === "") cells.pop();
        rows.push(cells);
        i++;
      }
      out.push("<table>");
      out.push("<thead><tr>" + headerCells.map((c) => `<th>${inline(c)}</th>`).join("") + "</tr></thead>");
      out.push("<tbody>");
      for (const r of rows) {
        out.push("<tr>" + r.map((c) => `<td>${inline(c.replace(/\\\|/g, "|"))}</td>`).join("") + "</tr>");
      }
      out.push("</tbody></table>");
      continue;
    }

    // Horizontal rule
    if (/^\s*---+\s*$/.test(line) || /^\s*___+\s*$/.test(line) || /^\s*\*\*\*+\s*$/.test(line)) {
      closeList(listStack);
      out.push("<hr />");
      i++;
      continue;
    }

    // Headings
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      closeList(listStack);
      const level = h[1].length;
      out.push(`<h${level}>${inline(h[2])}</h${level}>`);
      i++;
      continue;
    }

    // Unordered list
    const ul = line.match(/^\s*[-*+]\s+(.*)$/);
    if (ul) {
      if (listStack[listStack.length - 1] !== "ul") {
        closeList(listStack);
        out.push("<ul>");
        listStack.push("ul");
      }
      out.push(`<li>${inline(ul[1])}</li>`);
      i++;
      continue;
    }

    // Ordered list
    const ol = line.match(/^\s*\d+\.\s+(.*)$/);
    if (ol) {
      if (listStack[listStack.length - 1] !== "ol") {
        closeList(listStack);
        out.push("<ol>");
        listStack.push("ol");
      }
      out.push(`<li>${inline(ol[1])}</li>`);
      i++;
      continue;
    }

    // Blank line
    if (/^\s*$/.test(line)) {
      closeList(listStack);
      i++;
      continue;
    }

    // Paragraph
    closeList(listStack);
    out.push(`<p>${inline(line)}</p>`);
    i++;
  }
  closeList(listStack);
  return out.join("\n");
}
