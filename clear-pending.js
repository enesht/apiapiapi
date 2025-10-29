import Database from 'better-sqlite3';

const db = new Database('./akca.db');

// Clear all pending subscriptions
const result = db.prepare(`
  DELETE FROM subscriptions WHERE status = 'pending' AND nft_mint IS NULL
`).run();

console.log(`✅ Deleted ${result.changes} pending subscriptions`);

// Show remaining subscriptions
const subs = db.prepare('SELECT * FROM subscriptions').all();
console.log(`\n📋 Remaining subscriptions: ${subs.length}`);
subs.forEach(sub => {
  console.log(`  - ${sub.id}: ${sub.wallet} (${sub.plan}) - ${sub.status} - NFT: ${sub.nft_mint || 'null'}`);
});

db.close();
