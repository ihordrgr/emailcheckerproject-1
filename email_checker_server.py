if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Load environment variables
    port = int(os.environ.get('PORT', 5000))
    host = "0.0.0.0"
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Email Checker Server on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    logger.info(f"Supported providers: {', '.join(EMAIL_PROVIDERS.keys())}")
    
    # Start Flask server with production settings
    app.run(host=host, port=port, debug=debug, threaded=True)