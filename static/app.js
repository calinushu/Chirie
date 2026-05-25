(function () {
  function extensionFor(type) {
    if (type === "image/jpeg") return "jpg";
    if (type === "image/webp") return "webp";
    return "png";
  }

  function renderList(input, list) {
    if (!list) return;
    list.textContent = "";
    Array.from(input.files || []).forEach(function (file) {
      var item = document.createElement("span");
      item.textContent = file.name;
      list.appendChild(item);
    });
  }

  function appendFiles(input, files) {
    var transfer = new DataTransfer();
    Array.from(input.files || []).forEach(function (file) {
      transfer.items.add(file);
    });
    files.forEach(function (file) {
      transfer.items.add(file);
    });
    input.files = transfer.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function pastedImageFiles(event) {
    var items = Array.from((event.clipboardData && event.clipboardData.items) || []);
    return items
      .filter(function (item) {
        return item.kind === "file" && item.type.indexOf("image/") === 0;
      })
      .map(function (item, index) {
        var file = item.getAsFile();
        if (!file) return null;
        var timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        return new File([file], "pasted-bill-" + timestamp + "-" + (index + 1) + "." + extensionFor(file.type), {
          type: file.type || "image/png",
          lastModified: Date.now(),
        });
      })
      .filter(Boolean);
  }

  document.querySelectorAll("[data-paste-upload]").forEach(function (zone) {
    var form = zone.closest("form");
    if (!form) return;
    var input = form.querySelector('input[type="file"][name="bill_files"]');
    var list = zone.querySelector("[data-paste-upload-list]");
    if (!input) return;

    input.addEventListener("change", function () {
      renderList(input, list);
    });

    zone.addEventListener("paste", function (event) {
      var files = pastedImageFiles(event);
      if (!files.length) return;
      event.preventDefault();
      appendFiles(input, files);
      zone.classList.add("has-files");
      renderList(input, list);
    });

    zone.addEventListener("click", function () {
      zone.focus();
    });
  });
})();
