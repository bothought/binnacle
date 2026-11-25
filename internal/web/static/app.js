(() => {
  const log = document.getElementById("run-log");
  if (!log || log.dataset.live !== "1") return;
  const state = document.getElementById("run-state");
  let finished = false;
  let source;
  try {
    source = new EventSource(`/runs/${encodeURIComponent(log.dataset.run)}/events`);
  } catch (e) {
    if (state) state.textContent = "stream unavailable";
    return;
  }
  const finish = (text) => {
    if (finished) return;
    finished = true;
    source.close();
    if (state && text) state.textContent = text;
  };
  source.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (e) {
      return;
    }
    if (msg.chunk) {
      const nearBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 32;
      log.textContent += msg.chunk;
      if (nearBottom) log.scrollTop = log.scrollHeight;
    }
    if (msg.done) finish("finished");
  };
  source.onerror = () => finish("stream closed");
})();
