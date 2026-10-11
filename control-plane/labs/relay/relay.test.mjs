import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { startRelayLab } from './relay.mjs';

const devices = ['pc-um', 'pc-dois', 'pc-tres'].map(id => ({ id, secret: randomBytes(32).toString('hex') }));
const post = (url, device, body, secret = device.secret, path = '/v1/infer') => fetch(url + path, {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}`, 'x-ordax-lab-device-id': device.id },
  body: JSON.stringify(body),
});

test('3 PCs virtuais têm credenciais e resultados separados, sem lista de peers', async t => {
  const calls = [];
  const lab = await startRelayLab({ devices, inference: async input => { calls.push(input); return { deviceId:input.deviceId, requestId:input.requestId, result:`central:${input.deviceId}:${input.prompt}` }; } });
  t.after(() => lab.close());
  assert.match(lab.url, /^http:\/\/127\.0\.0\.1:/);
  const id = randomUUID();
  const replies = await Promise.all(devices.map(async device => {
    const res = await post(lab.url, device, { request_id: id, prompt: 'teste' });
    assert.equal(res.status, 200);
    return res.json();
  }));
  assert.equal(calls.length, 3);
  for (let i = 0; i < devices.length; i++) {
    assert.equal(replies[i].result, `central:${devices[i].id}:teste`);
    assert.equal(replies[i].source, 'lab-adapter');
    assert.equal(replies[i].replayed, false);
    assert.ok(!JSON.stringify(replies[i]).includes(devices[(i + 1) % 3].id));
  }
  const response = await fetch(lab.url + '/v1/devices');
  assert.equal(response.status, 404);
  assert.ok(!JSON.stringify(await response.json()).includes('pc-dois'));
  assert.equal((await post(lab.url, devices[0], { request_id: randomUUID(), prompt: 'toque' }, undefined, '/v1/infer/pc-dois')).status, 404);
  assert.equal((await post(lab.url, devices[0], { request_id: randomUUID(), prompt: 'toque', target_device_id: 'pc-dois' })).status, 400);
});

test('credencial roubada de outro PC, identificador trocado e campos extras são negados', async t => {
  let invoked = 0;
  const lab = await startRelayLab({ devices, inference: async input => { invoked++; return {deviceId:input.deviceId,requestId:input.requestId,result:'ok'}; } });
  t.after(() => lab.close());
  const body = { request_id: randomUUID(), prompt: 'ola' };
  assert.equal((await post(lab.url, devices[0], body, devices[1].secret)).status, 401);
  assert.equal((await post(lab.url, { ...devices[0], id: 'pc-inexistente' }, body)).status, 401);
  assert.equal((await post(lab.url, devices[0], { ...body, space_id: 'outro' })).status, 400);
  assert.equal(invoked, 0);
});

test('retries são idempotentes por dispositivo, nunca reutilizam saída de outro PC', async t => {
  let invoked = 0;
  const lab = await startRelayLab({ devices, inference: async ({deviceId,requestId}) => { invoked++; return {deviceId,requestId,result:deviceId}; } });
  t.after(() => lab.close());
  const body = { request_id: randomUUID(), prompt: 'ola' };
  let first = await (await post(lab.url, devices[0], body)).json();
  let retry = await (await post(lab.url, devices[0], body)).json();
  let other = await (await post(lab.url, devices[1], body)).json();
  assert.equal(first.replayed, false);
  assert.equal(retry.replayed, true);
  assert.equal(other.replayed, false);
  assert.equal(other.result, devices[1].id);
  assert.equal(invoked, 2);
  assert.equal((await post(lab.url, devices[0], { ...body, prompt: 'alterado' })).status, 409);
});

test('falhas de inferência não expõem conteúdo, credenciais nem acionam outro PC', async t => {
  const lab = await startRelayLab({ devices, inference: async () => { throw new Error('private provider token'); } });
  t.after(() => lab.close());
  const response = await post(lab.url, devices[2], { request_id: randomUUID(), prompt: 'conteudo privado' });
  assert.equal(response.status, 503);
  const body = await response.text();
  assert.ok(!body.includes('provider token'));
  assert.ok(!body.includes('conteudo privado'));
  assert.ok(!body.includes('pc-um'));
});

test('revogação central interrompe resposta pendente e não interfere em outros PCs', async t => {
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const lab = await startRelayLab({
    devices,
    inference: async ({ deviceId,requestId }) => deviceId === devices[0].id ? blocked.then(result=>({deviceId,requestId,result})) : {deviceId,requestId,result:'resultado-de-outro-cliente'},
  });
  t.after(() => lab.close());
  const firstRequest = post(lab.url, devices[0], {request_id:randomUUID(),prompt:'analise a pasta 1'});
  // Give the request time to reach the adapter. The test is not a proof of
  // external inference cancellation: it proves the late result cannot leak.
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(lab.revokeDevice(devices[0].id), true);
  assert.equal(lab.revokeDevice(devices[0].id), false);
  release('resposta atrasada nao autorizada');
  const first = await firstRequest;
  assert.equal(first.status, 401);
  assert.equal((await first.json()).error, 'unauthorized');
  const repeated = await post(lab.url, devices[0], {request_id:randomUUID(),prompt:'repetir'});
  assert.equal(repeated.status, 401);
  const other = await post(lab.url, devices[1], {request_id:randomUUID(),prompt:'requisicao independente'});
  assert.equal(other.status, 200);
  assert.equal((await other.json()).result, 'resultado-de-outro-cliente');
});

test('resposta com deviceId ou requestId de outro usuário é rejeitada sem revelar conteúdo',async t=>{
  const others = devices;
  const lab = await startRelayLab({devices:others,inference:async ({deviceId,requestId})=>({
    deviceId:deviceId === others[0].id ? others[1].id : deviceId,
    requestId:deviceId === others[2].id ? randomUUID() : requestId,
    result:'DADO_PRIVADO_NAO_PODE_SAIR',
  })});
  t.after(()=>lab.close());
  for(const d of [others[0],others[2]]){
    const response=await post(lab.url,d,{request_id:randomUUID(),prompt:'analise a pasta 1'});
    assert.equal(response.status,503);
    const body=await response.text();
    assert.ok(!body.includes('DADO_PRIVADO_NAO_PODE_SAIR'));
    assert.ok(!body.includes(others[1].secret));
  }
  const valid=await post(lab.url,others[1],{request_id:randomUUID(),prompt:'solicitacao valida'});
  assert.equal(valid.status,200);
  assert.equal((await valid.json()).result,'DADO_PRIVADO_NAO_PODE_SAIR');
});

test('cancelamento do mesmo cliente encerra uma solicitação sem repetir o adapter', async t => {
  let begin;
  const started = new Promise(resolve => { begin = resolve; });
  let executed = 0, observedSignal;
  const lab = await startRelayLab({
    devices,
    inferenceTimeoutMs: 5000,
    inference: async input => {
      executed++;
      observedSignal = input.signal;
      begin();
      return new Promise(() => {});
    },
  });
  t.after(() => lab.close());
  const requestId = randomUUID();
  const body = {request_id: requestId, prompt: 'analise a pasta 1'};
  const pending = post(lab.url, devices[0], body);
  await started;
  // A different PC may not cancel this request even with its request ID.
  const wrong = await post(lab.url, devices[1], { request_id: requestId }, undefined, '/v1/cancel');
  assert.equal(wrong.status, 202);
  assert.equal(observedSignal.aborted, false);
  const cancel = await post(lab.url, devices[0], { request_id: requestId }, undefined, '/v1/cancel');
  assert.equal(cancel.status, 202);
  assert.equal((await cancel.json()).accepted, true);
  const stopped = await pending;
  assert.equal(stopped.status, 409);
  assert.equal((await stopped.json()).error, 'request_cancelled');
  assert.equal(observedSignal.aborted, true);
  const retried = await post(lab.url, devices[0], body);
  assert.equal(retried.status, 409);
  assert.equal((await retried.json()).replayed, true);
  assert.equal(executed, 1);
});

test('timeout termina trabalho preso sem permitir reexecução do mesmo request ID', async t => {
  let executed = 0, signal;
  const lab = await startRelayLab({
    devices, inferenceTimeoutMs: 35,
    inference: async input => { executed++; signal = input.signal; return new Promise(() => {}); }
  });
  t.after(() => lab.close());
  const payload = {request_id:randomUUID(),prompt:'analisar conteudo'};
  const timedOut = await post(lab.url,devices[0],payload);
  assert.equal(timedOut.status,504);
  assert.equal((await timedOut.json()).error,'adapter_timeout');
  assert.equal(signal.aborted,true);
  const duplicate = await post(lab.url,devices[0],payload);
  assert.equal(duplicate.status,504);
  assert.equal((await duplicate.json()).replayed,true);
  assert.equal(executed,1);
});

test('falhas terminais e capacidade de recibos nunca fazem replay silencioso', async t => {
  let count = 0;
  const lab = await startRelayLab({
    devices,maxReceipts:2,
    inference:async ({deviceId,requestId}) => {
      count++;
      if(count===1) throw Error('secret-backend-stacktrace');
      return {deviceId,requestId,result:'ok'};
    }
  });
  t.after(()=>lab.close());
  const first = {request_id:randomUUID(),prompt:'primeiro'};
  assert.equal((await post(lab.url,devices[0],first)).status,503);
  const retry = await post(lab.url,devices[0],first);
  assert.equal(retry.status,503);
  assert.equal((await retry.json()).error,'adapter_unavailable');
  assert.equal((await post(lab.url,devices[1],{request_id:randomUUID(),prompt:'segundo'})).status,200);
  const blocked = await post(lab.url,devices[2],{request_id:randomUUID(),prompt:'terceiro'});
  assert.equal(blocked.status,503);
  assert.equal((await blocked.json()).error,'lab_receipt_capacity_exhausted');
  assert.equal(count,2);
  assert.equal((await post(lab.url,devices[0],first)).status,503);
  assert.equal(count,2);
});

test('tokens de dispositivo duplicados são recusados antes de iniciar qualquer conexão',async()=>{
  await assert.rejects(startRelayLab({devices:[devices[0],{...devices[1],secret:devices[0].secret}],
    inference:async()=>({})}),/duplicate_lab_credential/);
});
