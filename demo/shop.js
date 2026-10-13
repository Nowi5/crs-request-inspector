// Example Shop: renders products and produces the request mix shown in the README.
const SIG = 'Zm9vYmFy--Xk3Pq9vL2mN8aB7cD1eF4gH~Zr5Tt0Yy6Uu3Ii9Oo2Pp8Ll1Kk4Jj7Hh0Gg5~Ff2Dd9Ss6Aa3Qq-Ww8Ee1Rr4Tt7Yy-Uu0Ii3Oo6Pp9Zz-Nn2Mm5Bb8Vv1Cc4Xx7~Lk3Jh6Gf9Ds2Az5Qw8Er1Ty4Ui7Op0-Mn3Bv6Cx9Za2Sd5Fg8Hj1Kl4__';
const jsonReq = (method, url, body) => fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

async function browse() {
  const q = document.getElementById('search').value;
  const { items } = await (await fetch(`/api/products?search=${encodeURIComponent(q).replace(/%20/g, '+')}&page=1`)).json();
  const grid = document.getElementById('grid');
  grid.replaceChildren(...(items.length ? items : [{ id: 1042, name: 'Aurora Wireless Headphones', price: 129 }]).map((p) => {
    const card = document.createElement('article');
    card.className = 'card';
    const img = document.createElement('img');
    img.alt = p.name;
    img.src = `/images/products/${p.id}/hero.webp?Expires=1893456000&Signature=${SIG}&Key-Pair-Id=K2EXAMPLE`;
    const body = document.createElement('div');
    body.className = 'body';
    body.innerHTML = '<h3></h3><div class="price"></div>';
    body.querySelector('h3').textContent = p.name;
    body.querySelector('.price').textContent = `$${p.price}`;
    card.append(img, body);
    return card;
  }));
  await jsonReq('POST', '/api/cart/items', { productId: 1042, quantity: 2 });
  await jsonReq('POST', '/api/products/1042/reviews', { rating: 5, text: "Great sound! Select the 'bass boost' mode from the app – it works where others don't." });
  await jsonReq('PUT', '/api/account/profile', { displayName: 'Alex', newsletter: true });
}

async function attacks() {
  await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `username=admin&password=${encodeURIComponent("' OR '1'='1' --")}` });
  await fetch(`/api/search?q=${encodeURIComponent('<script>alert(document.cookie)</script>')}`);
  await fetch('/api/orders/77/invoice?file=../../../../etc/passwd');
  await fetch('/debug/orders');
}

document.getElementById('normal').addEventListener('click', browse);
document.getElementById('attacks').addEventListener('click', attacks);
browse().then(() => (new URLSearchParams(location.search).has('attacks') ? attacks() : null));
