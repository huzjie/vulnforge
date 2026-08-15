// Deliberately vulnerable JavaScript sample: eval + innerHTML (CWE-95 / CWE-79).
// DO NOT use this code in production.

function evaluateExpression(expr) {
  // vulnforge-static: eval-rce
  return eval(expr);
}

function renderComment(comment) {
  // vulnforge-static: xss
  document.getElementById('comment-box').innerHTML = comment;
}

function buildQuery(table, id) {
  // vulnforge-static: sql-injection
  return "SELECT * FROM " + table + " WHERE id = '" + id + "'";
}
