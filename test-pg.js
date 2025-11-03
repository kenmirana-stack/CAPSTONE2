const { Client } = require('pg');

// Connection string from the credentials you provided
const connectionString = 'postgresql://moonrider_user:n4eds0JzFo7Ysvq0okMThOD7J76e09Ce@dpg-d440am2li9vc73dikn70-a.oregon-postgres.render.com:5432/moonrider';

const client = new Client({
  connectionString,
  ssl: { rejectUnauthorized: false } // allow connecting even if certificate is not trusted (ok for testing)
});

(async () => {
  try {
    await client.connect();
    console.log('Connected to Postgres');
    const res = await client.query('SELECT NOW() as now');
    console.log('Server time:', res.rows[0].now);
  } catch (err) {
    console.error('Connection error:', err);
  } finally {
    await client.end();
  }
})();
