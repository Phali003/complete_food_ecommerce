const mysql = require("mysql2/promise");
const util = require("util");

async function testDB() {
  try {
    const connection = await mysql.createConnection({
      host: "localhost",
      user: "root",
      password: "mysql",
      database: "food_ecommerce"
    });
    
    const limit = 10;
    const offset = 0;
    const query = "SELECT * FROM products WHERE 1=1 ORDER BY name ASC LIMIT " + limit + " OFFSET " + offset;
    const [products] = await connection.execute(query);
    console.log("Query successful. Products:", util.inspect(products, { depth: null, colors: true }));
    await connection.end();
  } catch (error) {
    console.error("Error:", error);
  }
}

testDB();
