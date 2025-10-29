import Database from 'better-sqlite3';

const db = new Database('akca.db');

try {
  console.log('Clearing all tables...');

  db.prepare('DELETE FROM subscriptions').run();
  db.prepare('DELETE FROM payments').run();

  console.log('✅ Database cleared successfully');

  const paymentCount = db.prepare('SELECT COUNT(*) as count FROM payments').get();
  const subCount = db.prepare('SELECT COUNT(*) as count FROM subscriptions').get();

  console.log(`Payments: ${paymentCount.count}`);
  console.log(`Subscriptions: ${subCount.count}`);
} catch (error) {
  console.error('Error:', error);
} finally {
  db.close();
}
