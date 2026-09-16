const $ = (selector) => document.querySelector(selector);
const toast = (message, error = false) => { const node = $('#toast'); node.textContent = message; node.style.background = error ? '#ffc1bb' : '#d9f5b5'; node.classList.add('show'); setTimeout(() => node.classList.remove('show'), 3200); };

function render(data) {
  $('#packet-count').textContent = data.packet_count ?? '--';
  $('#protocol-count').textContent = data.protocols?.length ?? '--';
  $('#alert-count').textContent = data.suspicious?.length ?? '0';
  const bars = $('#protocol-bars');
  if (!data.protocols?.length) { bars.className = 'bars empty-state'; bars.innerHTML = '<p>No recognized protocols in this result.</p>'; }
  else { const max = Math.max(...data.protocols.map(item => item.count)); bars.className = 'bars'; bars.innerHTML = data.protocols.map(item => `<div class="bar-group"><span class="bar-value">${item.count}</span><div class="bar" style="height:${Math.max(5, item.count / max * 105)}px"></div><span class="bar-label">${item.name}</span></div>`).join(''); }
  const table = $('#packet-table');
  table.innerHTML = data.packets?.length ? data.packets.slice().reverse().map(packet => `<tr><td>${packet.time}</td><td>${packet.source}</td><td>${packet.destination}</td><td><span class="protocol-tag">${packet.protocol}</span></td><td>${packet.length} B</td><td>${packet.port ? `port ${packet.port}` : packet.flags || '-'}</td></tr>`).join('') : '<tr><td colspan="6" class="empty-table">No packets in view yet.</td></tr>';
}

async function runCommand(command, authorized = false) { const response = await fetch('/api/command', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({command, authorized}) }); const body = await response.json(); if (!response.ok) throw new Error(body.detail || 'Command failed'); render(body.data); toast(body.summary); }
$('#command-form').addEventListener('submit', async (event) => { event.preventDefault(); const button = event.currentTarget.querySelector('button[type=submit]'); button.disabled = true; button.textContent = 'Working...'; try { await runCommand($('#command-input').value); } catch (error) { toast(error.message, true); } finally { button.disabled = false; button.innerHTML = 'Run analysis <span>-></span>'; } });
document.querySelectorAll('[data-command]').forEach(button => button.addEventListener('click', () => { $('#command-input').value = button.dataset.command; $('#command-form').requestSubmit(); }));
$('#pcap-input').addEventListener('change', async (event) => { const file = event.target.files[0]; if (!file) return; const form = new FormData(); form.append('file', file); $('#upload-status').textContent = 'Reading capture...'; try { const response = await fetch('/api/upload', {method:'POST', body:form}); const body = await response.json(); if (!response.ok) throw new Error(body.detail); render(body); $('#upload-status').textContent = `${file.name} loaded`; toast(`Analyzed ${file.name}`); } catch(error) { $('#upload-status').textContent = 'Upload failed'; toast(error.message, true); } });
$('#clear-button').addEventListener('click', () => render({packet_count: 0, protocols: [], suspicious: [], packets: []}));
