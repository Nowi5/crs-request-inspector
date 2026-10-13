// Aho-Corasick multi-phrase matcher used for @pm / @pmFromFile.
// Phrases and input must already be case-folded by the caller.

export class AhoCorasick {
  /** @param {string[]} phrases */
  constructor(phrases) {
    this.goto = [new Map()];
    this.fail = [0];
    this.out = [null]; // shortest-ending phrase index (length) at node
    for (const p of phrases) {
      if (!p) continue;
      let node = 0;
      for (let i = 0; i < p.length; i++) {
        const c = p.charCodeAt(i);
        let next = this.goto[node].get(c);
        if (next === undefined) {
          next = this.goto.length;
          this.goto.push(new Map());
          this.fail.push(0);
          this.out.push(null);
          this.goto[node].set(c, next);
        }
        node = next;
      }
      if (this.out[node] === null) this.out[node] = p;
    }
    // BFS to build failure links; propagate outputs (keep the longest phrase ending here).
    const queue = [];
    for (const [, n] of this.goto[0]) queue.push(n);
    while (queue.length) {
      const r = queue.shift();
      for (const [c, s] of this.goto[r]) {
        queue.push(s);
        let f = this.fail[r];
        while (f && !this.goto[f].has(c)) f = this.fail[f];
        const g = this.goto[f].get(c);
        this.fail[s] = g !== undefined && g !== s ? g : 0;
        if (this.out[s] === null) this.out[s] = this.out[this.fail[s]];
      }
    }
  }

  /** @returns {{start: number, end: number, phrase: string} | null} first (earliest ending) match */
  search(text) {
    let node = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      while (node && !this.goto[node].has(c)) node = this.fail[node];
      node = this.goto[node].get(c) ?? 0;
      const p = this.out[node];
      if (p !== null) return { start: i + 1 - p.length, end: i + 1, phrase: p };
    }
    return null;
  }
}
