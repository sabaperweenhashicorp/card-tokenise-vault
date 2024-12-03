mkdir -p lambda_layer/python
pip install hvac -t lambda_layer/python
cd lambda_layer
zip -r ../lambda_layer.zip python/
cd ..
zip lambda_function.zip lambda_function.py