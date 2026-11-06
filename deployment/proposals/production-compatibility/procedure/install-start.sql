INSERT INTO d1_cveharbor_repair_receipts(id,payload) SELECT 'install-started',payload FROM d1_cveharbor_repair_receipts WHERE id='install-intent';
