(() => {
  "use strict";

  const emailPattern = /[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,}/gi;
  const displayAttributes = ["title", "aria-label", "alt", "placeholder"];

  function maskEmails(text) {
    return text.replace(emailPattern, (email) => {
      // Provider prefixes belong to credential filenames, not the email address.
      const prefix = email.toLowerCase().endsWith(".json")
        ? email.match(/^(?:codex|antigravity|claude|xai|gemini|kimi|qwen|iflow)-/i)?.[0] || ""
        : "";
      const at = email.indexOf("@");
      const visible = email.slice(prefix.length, at).replace(/\*+$/, "").slice(0, 2);
      return prefix + visible + "***" + email.slice(at);
    });
  }

  function updateText(node) {
    if (node.parentElement?.closest("script, style, textarea, input, [contenteditable]")) return;
    const next = maskEmails(node.nodeValue || "");
    if (node.nodeValue !== next) node.nodeValue = next;
  }

  function updateElement(element) {
    for (const attribute of displayAttributes) {
      const current = element.getAttribute(attribute);
      if (current === null) continue;
      const next = maskEmails(current);
      if (current !== next) element.setAttribute(attribute, next);
    }
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
      // Conceal email-containing form values without changing submitted credentials.
      element.classList.toggle("cpa-private-email", emailPattern.test(element.value));
      emailPattern.lastIndex = 0;
    }
  }

  function updateTree(root) {
    if (root.nodeType === Node.TEXT_NODE) {
      updateText(root);
      return;
    }
    if (!(root instanceof Element)) return;
    updateElement(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        return node instanceof Element && node.matches("script, style")
          ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
      },
    });
    while (walker.nextNode()) {
      if (walker.currentNode.nodeType === Node.TEXT_NODE) updateText(walker.currentNode);
      else updateElement(walker.currentNode);
    }
  }

  function start() {
    const style = document.createElement("style");
    style.textContent = ".cpa-private-email { -webkit-text-security: disc !important; }";
    document.head.append(style);
    updateTree(document.body);
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "childList") mutation.addedNodes.forEach(updateTree);
        else if (mutation.type === "characterData") updateText(mutation.target);
        else updateElement(mutation.target);
      }
    });
    observer.observe(document.body, {
      childList: true, subtree: true, characterData: true,
      attributes: true, attributeFilter: [...displayAttributes, "value"],
    });
    document.addEventListener("input", (event) => {
      if (event.target instanceof Element) updateElement(event.target);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
