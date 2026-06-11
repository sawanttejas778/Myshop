@app.route('/api/create_pr', methods=['POST'])
@login_required
def create_pr():
    data = request.get_json()
    conn = get_db_connection()
    
    try:
        shop_id = data.get('shopid')
        supplier_id = data.get('supplier_id')
        reason = data.get('reason', '')
        items = data.get('items', [])
        convert_to_po = data.get('convert_to_po', False)
        
        # Validation
        if not shop_id:
            return jsonify({'success': False, 'message': 'Shop ID required'}), 400
        if not supplier_id:
            return jsonify({'success': False, 'message': 'Supplier ID required'}), 400
        if not items:
            return jsonify({'success': False, 'message': 'At least one item required'}), 400
        
        with conn.cursor() as cursor:
            # Calculate totals if not provided
            subtotal = data.get('subtotal', 0)
            tax_amount = data.get('tax_amount', 0)
            grand_total = data.get('grand_total', 0)
            
            if not subtotal:
                subtotal = sum(item['quantity'] * item['unit_price'] for item in items)
                tax_amount = sum(item['tax_amount'] for item in items)
                grand_total = subtotal + tax_amount
            
            # 1. Insert into purchase_reciepts
            cursor.execute("""
                INSERT INTO purchase_reciepts (shopid, supplier_id, Reason, created_by, updated_by)
                VALUES (%s, %s, %s, %s, %s)
            """, (shop_id, supplier_id, reason, session['userid'], session['userid']))
            
            pr_id = cursor.lastrowid
            pr_number = f"PR-{pr_id:04d}"
            
            # 2. Insert items into PR_items
            for item in items:
                product_id = item.get('product_id')
                if not product_id:
                    # Try to get product_id by name if not provided
                    cursor.execute("SELECT product_id FROM Products WHERE name = %s AND shop_id = %s LIMIT 1", 
                                  (item['product_name'], shop_id))
                    product = cursor.fetchone()
                    product_id = product['product_id'] if product else None
                
                if not product_id:
                    continue  # Skip if product not found
                
                cursor.execute("""
                    INSERT INTO PR_items (shopid, PRID, product_id, quantity, unit_price, tax_rate, tax_amount, total)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (shop_id, pr_id, product_id, item['quantity'], item['unit_price'], 
                      item['tax_rate'], item['tax_amount'], item['total']))
            
            conn.commit()
            
            # 3. Optionally create PO immediately
            po_result = None
            if convert_to_po:
                po_result = create_po_from_pr(conn, pr_id, shop_id, supplier_id, items, session['userid'])
            
            return jsonify({
                'success': True,
                'message': 'Purchase Requisition created successfully',
                'pr_id': pr_id,
                'pr_number': pr_number,
                'po_created': convert_to_po,
                'po_result': po_result
            })
            
    except Exception as e:
        conn.rollback()
        print(f"Error creating PR: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()


def create_po_from_pr(conn, pr_id, shop_id, supplier_id, items, created_by):
    """Helper function to create PO from existing PR"""
    try:
        with conn.cursor() as cursor:
            # Calculate totals
            total_qty = sum(item['quantity'] for item in items)
            subtotal = sum(item['quantity'] * item['unit_price'] for item in items)
            tax_total = sum(item['tax_amount'] for item in items)
            grand_total = subtotal + tax_total
            
            # Generate PO number
            cursor.execute("SELECT COUNT(*) as count FROM purchase_orders WHERE shopid = %s", (shop_id,))
            count = cursor.fetchone()
            po_number = f"PO-{count['count'] + 1:04d}"
            
            # Insert into purchase_orders
            cursor.execute("""
                INSERT INTO purchase_orders (PRID, supplier_id, shopid, Status, INFONO, tax, QTY, price, total, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (pr_id, supplier_id, shop_id, 'pending', po_number, 
                  tax_total, total_qty, subtotal, grand_total, created_by))
            
            po_id = cursor.lastrowid
            conn.commit()
            
            return {
                'po_id': po_id,
                'po_number': po_number,
                'total': grand_total
            }
    except Exception as e:
        print(f"Error creating PO: {e}")
        return None


@app.route('/api/create_po_from_pr/<int:pr_id>', methods=['POST'])
@login_required
def create_po_from_existing_pr(pr_id):
    """
    Creates Purchase Order from an existing Purchase Requisition
    Reuses items from PR_items table (no duplicate storage)
    """
    conn = get_db_connection()
    
    try:
        shop_id = get_shop_id(session['userid'])
        
        with conn.cursor() as cursor:
            # Get PR details
            cursor.execute("""
                SELECT pr.receipt_id, pr.shopid, pr.supplier_id, pr.Reason
                FROM purchase_reciepts pr
                WHERE pr.receipt_id = %s AND pr.shopid = %s
            """, (pr_id, shop_id))
            
            pr = cursor.fetchone()
            if not pr:
                return jsonify({'success': False, 'message': 'PR not found'}), 404
            
            # Get items from PR_items (reuse existing data)
            cursor.execute("""
                SELECT pi.product_id, pi.quantity, pi.unit_price, pi.tax_rate, pi.tax_amount, pi.total,
                       p.name as product_name
                FROM PR_items pi
                JOIN Products p ON pi.product_id = p.product_id
                WHERE pi.PRID = %s AND pi.shopid = %s
            """, (pr_id, shop_id))
            
            items = cursor.fetchall()
            
            if not items:
                return jsonify({'success': False, 'message': 'No items found in PR'}), 400
            
            # Check if PO already exists for this PR
            cursor.execute("SELECT PONO FROM purchase_orders WHERE PRID = %s AND shopid = %s", (pr_id, shop_id))
            existing_po = cursor.fetchone()
            if existing_po:
                return jsonify({
                    'success': False, 
                    'message': f'PO already exists for this PR',
                    'existing_po_id': existing_po['PONO']
                }), 400
            
            # Calculate totals from items
            total_qty = sum(item['quantity'] for item in items)
            subtotal = sum(item['quantity'] * item['unit_price'] for item in items)
            tax_total = sum(item['tax_amount'] for item in items)
            grand_total = subtotal + tax_total
            
            # Generate PO number
            cursor.execute("SELECT COUNT(*) as count FROM purchase_orders WHERE shopid = %s", (shop_id,))
            count = cursor.fetchone()
            po_number = f"PO-{count['count'] + 1:04d}"
            
            # Insert into purchase_orders
            cursor.execute("""
                INSERT INTO purchase_orders (PRID, supplier_id, shopid, Status, INFONO, tax, QTY, price, total, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (pr_id, pr['supplier_id'], shop_id, 'pending', po_number, 
                  tax_total, total_qty, subtotal, grand_total, session['userid']))
            
            po_id = cursor.lastrowid
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Purchase Order created successfully',
                'po_id': po_id,
                'po_number': po_number,
                'pr_id': pr_id,
                'pr_number': f"PR-{pr_id:04d}",
                'total': grand_total,
                'items_count': len(items)
            })
            
    except Exception as e:
        conn.rollback()
        print(f"Error creating PO from PR: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/get_pr/<int:pr_id>', methods=['GET'])
@login_required
def get_pr_details(pr_id):
    """Get PR with its items (reuses PR_items table)"""
    conn = get_db_connection()
    
    try:
        shop_id = get_shop_id(session['userid'])
        
        with conn.cursor() as cursor:
            # Get PR header
            cursor.execute("""
                SELECT pr.receipt_id, pr.shopid, pr.supplier_id, pr.Reason, pr.created_at, pr.created_by,
                       s.name as supplier_name
                FROM purchase_reciepts pr
                LEFT JOIN supplier s ON pr.supplier_id = s.supplier_id
                WHERE pr.receipt_id = %s AND pr.shopid = %s
            """, (pr_id, shop_id))
            
            pr = cursor.fetchone()
            if not pr:
                return jsonify({'success': False, 'message': 'PR not found'}), 404
            
            # Get items from PR_items
            cursor.execute("""
                SELECT pi.id, pi.product_id, p.name as product_name, pi.quantity, 
                       pi.unit_price, pi.tax_rate, pi.tax_amount, pi.total
                FROM PR_items pi
                JOIN Products p ON pi.product_id = p.product_id
                WHERE pi.PRID = %s AND pi.shopid = %s
            """, (pr_id, shop_id))
            
            items = cursor.fetchall()
            
            # Calculate totals
            subtotal = sum(item['quantity'] * item['unit_price'] for item in items)
            tax_total = sum(item['tax_amount'] for item in items)
            grand_total = subtotal + tax_total
            
            return jsonify({
                'success': True,
                'pr': {
                    'id': pr['receipt_id'],
                    'pr_number': f"PR-{pr['receipt_id']:04d}",
                    'supplier_id': pr['supplier_id'],
                    'supplier_name': pr['supplier_name'],
                    'reason': pr['Reason'],
                    'created_at': pr['created_at'].strftime('%Y-%m-%d %H:%M:%S') if pr['created_at'] else None,
                    'created_by': pr['created_by'],
                    'items': items,
                    'subtotal': subtotal,
                    'tax_amount': tax_total,
                    'grand_total': grand_total
                }
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()