from sqlconnection import get_db

def GSTR9C_report():
    conn,cursor = get_db()

def ledger(cursor, partyid, partytype, amount, transactiontype, transaction_id, transaction_date):
    query = "INSERT INTO ledger(partyid, partytype,transactiontype, amount, transaction_id, transaction_date) VALUES (%s, %s, %s, %s, %s, %s)"
    cursor.execute(query, (partyid, partytype, transactiontype, amount, transaction_id, transaction_date))
