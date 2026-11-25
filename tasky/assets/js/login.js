"use strict";

for (const form of document.querySelectorAll("form")) {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const error = form.querySelector(".error");
    const button = form.querySelector("button");
    error.textContent = "";
    button.disabled = true;
    try {
      const response = await fetch("/" + form.id, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
      });
      if (response.ok) {
        window.location.assign("/todo");
      } else {
        error.textContent = (await response.json()).error;
      }
    } catch {
      error.textContent = "Unable to reach Tasky. Please try again.";
    } finally {
      button.disabled = false;
    }
  });
}
