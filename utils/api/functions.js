/**
 *
 * @param {object} db
 * @param {object} schema
 * @param {string} tableName
 */
exports.createTable = function (db, schema = {}, tableName) {
  // validating type of schema if it is object or not
  if (typeof schema !== "object") {
    return new Error("schema must be an object");
  }

  //   validating if schema object is empty.
  if (!Object.entries(schema).length) {
    return new Error("your schema is either empty or you forgot to pass");
  }

  //   validating type of `tableName` parameter
  if (typeof tableName !== "string") {
    return new Error("Table name must be string");
  }

  //   validating if `tableName` parameter is empty or not.
  if (!tableName) {
    return new Error("table name can not be empty.");
  }

  //   Validate the type of db (database pool)
  if (typeof db !== "object") {
    throw new Error("Invalid databse pool");
  }

  const formate = Object.keys(schema)
    .map((key) => `${key} ${schema[key].type}`)
    .join(",");
  console.log(formate);
  try {
    const query = `CREATE TABLE IF NOT EXISTS dark.${tableName} (
                    id SERIAL PRIMARY KEY,
                    ${formate}
                )`;
    db.query(query);
  } catch (error) {
    throw new Error(error);
  }
};

/**
 *
 * @param {object} db
 * @param {object} cols
 * @param {object} data
 * @param {string} tableName
 */
exports.insertData = async function (db, cols = [], data = [], tableName) {
  if (typeof cols !== "object" || typeof data !== "object") {
    return new Error("type of parameter is invalid");
  }

  if (!cols.length) {
    return new Error("cols parameter can not be empty.");
  }

  if (!data.length) {
    return new Error("data can not be empty");
  }
  //   validating type of `tableName` parameter
  if (typeof tableName !== "string") {
    return new Error("table name must be a string");
  }

  //   validating if `tableName` parameter is empty or not.
  if (!tableName) {
    return new Error("table name can not be empty.");
  }

  //   Validate the type of db (database pool)
  if (typeof db !== "object") {
    throw new Error("Invalid databse pool");
  }

  const formatedData = data.map((_, i) => `$${i + 1}`).join(",");
  console.log(tableName, formatedData, cols.join(","));
  const insertQuery = `INSERT INTO dark.${tableName} (${cols.join(",")})
                        VALUES (${formatedData})`;

  try {
    const result = await db.query(insertQuery, data);
    console.log(result);
  } catch (error) {
    return new Error(error);
  }
};
