"use strict";

const page = document.querySelector(".wrapper");
const owner = encodeURIComponent(page.dataset.userId);
const input = document.querySelector(".task-input input");
const list = document.querySelector(".task-box");
const clear = document.querySelector(".clear-btn");
const filters = document.querySelectorAll(".filters button");
const error = document.querySelector("#error");
document.querySelector("#username").textContent = page.dataset.displayName || "My tasks";

let todos = [];
let filter = "all";
let editing = null;
let busy = false;

function button(text, click) {
  const element = document.createElement("button");
  element.type = "button";
  element.textContent = text;
  element.addEventListener("click", click);
  return element;
}

function render() {
  list.replaceChildren();
  for (const todo of todos.filter(task => filter === "all" || task.status === filter)) {
    const row = document.createElement("li");
    row.className = "task";
    const label = document.createElement("label");
    const check = document.createElement("input");
    check.type = "checkbox";
    check.checked = todo.status === "completed";
    check.addEventListener("change", () => {
      const status = check.checked ? "completed" : "pending";
      mutate("/todo", "PUT", {...todo, status});
    });
    const text = document.createElement("p");
    text.textContent = todo.name;
    text.classList.toggle("checked", check.checked);
    label.append(check, text);
    const actions = document.createElement("div");
    actions.className = "settings";
    actions.append(button("Edit", () => {
      editing = todo.ID;
      input.value = todo.name;
      input.focus();
    }), button("Delete", () => mutate("/todo/" + owner + "/" + todo.ID, "DELETE")));
    row.append(label, actions);
    list.append(row);
  }
  if (!list.children.length) {
    const empty = document.createElement("li");
    empty.textContent = "You don't have any tasks here";
    list.append(empty);
  }
  clear.disabled = todos.length === 0;
  clear.classList.toggle("active", !clear.disabled);
}

async function request(path, method = "GET", payload) {
  const options = {method};
  if (payload) {
    options.headers = {"Content-Type": "application/json"};
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  if (response.status === 401) {
    window.location.replace("/");
    throw new Error("Session expired");
  }
  if (!response.ok) throw new Error("Task request failed");
  return response.json();
}

async function refresh() {
  todos = await request("/todos/" + owner);
  render();
}

async function mutate(path, method, payload) {
  if (busy) return;
  busy = true;
  page.inert = true;
  error.textContent = "";
  try {
    await request(path, method, payload);
    editing = null;
    input.value = "";
    await refresh();
  } catch {
    render();
    error.textContent = "Could not finish the request. Reload to see your current tasks.";
  } finally {
    busy = false;
    page.inert = false;
  }
}

for (const element of filters) {
  element.addEventListener("click", () => {
    filter = element.id;
    for (const item of filters) {
      item.classList.toggle("active", item === element);
      item.setAttribute("aria-pressed", String(item === element));
    }
    render();
  });
}
clear.addEventListener("click", () => mutate("/todos/" + owner, "DELETE"));
document.querySelector(".task-input").addEventListener("submit", event => {
  event.preventDefault();
  const name = input.value.trim();
  if (!name) return;
  const task = todos.find(todo => todo.ID === editing);
  if (task) mutate("/todo", "PUT", {...task, name});
  else mutate("/todo/" + owner, "POST", {name, status: "pending"});
});

refresh().catch(() => { error.textContent = "Could not load your tasks."; });
