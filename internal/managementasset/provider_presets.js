(() => {
  "use strict";

  const categoryID = "cpa-deepseek-category";
  const categorySelector = 'button[class*="ProviderCategoryList-module__item___"]';
  let selected = false;
  let selecting = false;
  let creating = false;
  let previousSearch = "";

  function fill(input, value) {
    if (input.value === value) return;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function nativeCategory() {
    return [...document.querySelectorAll(categorySelector)].find((button) =>
      button.id !== categoryID && /^OpenAI/.test(button.textContent.trim())
    );
  }

  function searchInput() {
    return document.querySelector('input[type="search"]');
  }

  function update() {
    if (!location.hash.startsWith("#/ai-providers")) {
      selected = false;
      creating = false;
      document.getElementById(categoryID)?.remove();
      return;
    }
    const native = nativeCategory();
    if (!native) return;
    let category = document.getElementById(categoryID);
    if (!category) {
      category = native.cloneNode(true);
      category.id = categoryID;
      category.querySelectorAll("img").forEach((image) => image.remove());
      category.querySelector('[class*="__itemTitle___"]').textContent = "DeepSeek";
      category.querySelector('[class*="__itemSubtitle___"]').textContent = "OpenAI-compatible API";
      category.querySelector('[class*="__badge___"]')?.remove();
      category.addEventListener("click", () => {
        if (document.querySelector('[role="dialog"]')) return;
        if (!selected) previousSearch = searchInput()?.value || "";
        selected = true;
        selecting = true;
        nativeCategory()?.click();
        selecting = false;
        update();
      });
      native.after(category);
    }

    const activeClass = [...document.querySelectorAll(categorySelector)]
      .flatMap((button) => [...button.classList])
      .find((name) => name.startsWith("ProviderCategoryList-module__active___"));
    if (activeClass) {
      category.classList.toggle(activeClass, selected);
      if (selected) native.classList.remove(activeClass);
    }
    category.setAttribute("aria-pressed", String(selected));
    if (!selected) return;

    const heading = document.querySelector('[class*="ProviderResourcePanel"] h2');
    if (heading && heading.textContent !== "DeepSeek") heading.textContent = "DeepSeek";
    const search = searchInput();
    if (search) fill(search, "deepseek");

    if (creating) {
      const dialog = document.querySelector('[role="dialog"]');
      const name = dialog?.querySelector('input[id$="-name"]');
      const baseURL = dialog?.querySelector('input[id$="-baseUrl"]');
      if (name && baseURL) {
        creating = false;
        fill(name, "deepseek");
        fill(baseURL, "https://api.deepseek.com");
        const title = dialog.querySelector("h2");
        if (title) title.textContent = title.textContent.replace(/OpenAI.*/, "DeepSeek");
        dialog.querySelector('input[type="password"]')?.focus();
      }
    }
  }

  function start() {
    document.addEventListener("click", (event) => {
      const button = event.target instanceof Element ? event.target.closest("button") : null;
      if (!button || !location.hash.startsWith("#/ai-providers")) return;
      if (button.matches(categorySelector) && button.id !== categoryID && !selecting) {
        if (document.querySelector('[role="dialog"]')) return;
        if (selected) {
          selected = false;
          creating = false;
          const heading = document.querySelector('[class*="ProviderResourcePanel"] h2');
          const nativeTitle = nativeCategory()?.querySelector('[class*="__itemTitle___"]');
          if (heading && nativeTitle) heading.textContent = nativeTitle.textContent;
          const search = searchInput();
          if (search) fill(search, previousSearch);
        }
      }
      if (selected && !document.querySelector('[role="dialog"]') && (
        button.className.includes("ProviderHeaderCard-module__btnPrimary") ||
        button.className.includes("ProviderResourcePanel-module__emptyActionButton")
      )) creating = true;
    }, true);
    new MutationObserver(update).observe(document.body, { childList: true, subtree: true });
    window.addEventListener("hashchange", update);
    update();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
