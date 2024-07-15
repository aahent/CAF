import os
import boto3
import uuid
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, session, url_for, flash, make_response
from dotenv import load_dotenv
import json
import random
import string
import pyotp
import qrcode
import io
import bcrypt
import sqlite3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pymongo
import subprocess



load_dotenv()

app = Flask(__name__)

# AWS credentials
AWS_REGION = os.environ.get('AWS_REGION')
ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')




###Connect to EC2
ec2_client = boto3.client('ec2', region_name=AWS_REGION,
                          aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=SECRET_ACCESS_KEY)

# Connect to VPC
vpc_client = boto3.client('ec2', region_name=AWS_REGION,
                          aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=SECRET_ACCESS_KEY)

# Connect to S3 
s3_client = boto3.client('s3', region_name=AWS_REGION,
                         aws_access_key_id=ACCESS_KEY_ID,
                         aws_secret_access_key=SECRET_ACCESS_KEY)

#connect to SQS
sqs = boto3.client('sqs', region_name=AWS_REGION,
                   aws_access_key_id=ACCESS_KEY_ID,
                   aws_secret_access_key=SECRET_ACCESS_KEY)

#connet to SNS
sns_client = boto3.client('sns', region_name=AWS_REGION,
                          aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=SECRET_ACCESS_KEY)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION,
                          aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=SECRET_ACCESS_KEY)

# LB
elb_client = boto3.client(
    'elbv2',
    region_name=AWS_REGION,
    aws_access_key_id=ACCESS_KEY_ID,
    aws_secret_access_key=SECRET_ACCESS_KEY
)

### SES(Simple Email Service)
ses_client = boto3.client('ses', region_name=AWS_REGION,
                          aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=SECRET_ACCESS_KEY)

#### Codecommit
codecommit_client = boto3.client('codecommit',
                                 region_name=AWS_REGION,
                                 aws_access_key_id=ACCESS_KEY_ID,
                                 aws_secret_access_key=SECRET_ACCESS_KEY)

# Initialize the Boto3 client for CodeBuild
codebuild_client = boto3.client('codebuild',
                                 region_name=AWS_REGION,
                                 aws_access_key_id=ACCESS_KEY_ID,
                                 aws_secret_access_key=SECRET_ACCESS_KEY)




iam_client = boto3.client(
    'iam',
    region_name=AWS_REGION,
    aws_access_key_id=ACCESS_KEY_ID,
    aws_secret_access_key=SECRET_ACCESS_KEY
)



ecs_client = boto3.client(
    'ecs',
    region_name=AWS_REGION,
    aws_access_key_id=ACCESS_KEY_ID,
    aws_secret_access_key=SECRET_ACCESS_KEY
)



#### Codecommit
codecommit_client = boto3.client('codecommit',
                                 region_name=AWS_REGION,
                                 aws_access_key_id=ACCESS_KEY_ID,
                                 aws_secret_access_key=SECRET_ACCESS_KEY)


client = boto3.client('codedeploy',
                      region_name=AWS_REGION,
                      aws_access_key_id=ACCESS_KEY_ID,
                      aws_secret_access_key=SECRET_ACCESS_KEY)


####### Two factor  Authentication code
app.secret_key = 'your_secret_key'

mongo_client = pymongo.MongoClient("mongodb://localhost:27017/") 
db = mongo_client['CAF']
users_collection = db["CAF"]

def load_users():
    users = {}
    for user in users_collection.find():
        username = user['username']
        users[username] = user
    return users

def save_user(user):
    users_collection.update_one(
        {'username': user['username']},
        {'$set': user},
        upsert=True
    )
    print(f"User {user['username']} saved to MongoDB.")

users = load_users()

def generate_otp_secret():
    return pyotp.random_base32()

def send_otp_via_email(email, otp):
    sender_email = "shubhamkale9112@gmail.com"
    sender_password = "hyeo rrug xasl oxis"
    receiver_email = email

    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.close()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    if username in users:
        flash('Username already exists!', 'error')
        return redirect(url_for('index'))

    # Hash the password before saving it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    otp_secret = generate_otp_secret()
    user = {'username': username, 'password': hashed_password, 'email': email, 'otp_secret': otp_secret}
    users[username] = user
    save_user(user)

    flash('Sign up successful! Please sign in.', 'success')
    return redirect(url_for('index'))

@app.route('/signin', methods=['POST'])
def signin():
    username = request.form['username']
    password = request.form['password']

    user = users.get(username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        flash('Invalid credentials', 'error')
        return redirect(url_for('index'))

    session['username'] = username
    return redirect(url_for('two_factor_auth'))

@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']
    otp_secret = users[username]['otp_secret']
    totp = pyotp.TOTP(otp_secret)

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            session['authenticated'] = True
            return redirect(url_for('CloudSelect'))
        else:
            flash('Invalid OTP', 'error')
            return redirect(url_for('two_factor_auth'))

    return render_template('two_factor_auth.html', username=username, otp_secret=otp_secret)

@app.route('/qr_code')
def qr_code():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']
    otp_secret = users[username]['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name='FlaskAuthApp')

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    response = make_response(buf.read())
    response.headers['Content-Type'] = 'image/png'
    return response

@app.route('/clouds')
def clouds():
    if 'authenticated' not in session:
        return redirect(url_for('index'))

    username = session['username']
    user_info = users.get(username)

    return render_template('clouds.html', username=username, user_info=user_info)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        for username, user in users.items():
            if user['email'] == email:
                otp = ''.join(random.choices(string.digits, k=6))
                session['reset_otp'] = otp
                session['reset_username'] = username
                send_otp_via_email(email, otp)
                flash('OTP sent to your email', 'info')
                return redirect(url_for('reset_password'))
        flash('Email not found', 'error')

    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']

        if otp == session.get('reset_otp'):
            username = session.get('reset_username')
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            users[username]['password'] = hashed_password
            save_user(users[username])
            flash('Password reset successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid OTP', 'error')

    return render_template('reset_password.html')

@app.route('/check_mongodb')
def check_mongodb():
    try:
        client.admin.command('ping')
        return jsonify(status='success', message='MongoDB is connected')
    except errors.ConnectionError:
        return jsonify(status='error', message='Failed to connect to MongoDB')

@app.route('/save-aws-credentials', methods=['POST'])
def save_aws_credentials():
    if 'username' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    username = session['username']
    access_key_id = request.form['access_key_id']
    secret_access_key = request.form['secret_access_key']
    region = request.form['region']

    # Update the user's AWS credentials in the database
    users[username]['aws_credentials'] = {
        'access_key_id': access_key_id,
        'secret_access_key': secret_access_key,
        'region': region
    }
    save_user(users[username])

    return jsonify({'message': 'Credentials saved successfully', 'redirect': url_for('clouds')})


###### end of the two factor authentication code



##routes for multiple pages
@app.route('/CloudSelect')
def CloudSelect():
    return render_template('CloudSelect.html')

@app.route('/')
def land():
    return render_template('land.html')


# UI

@app.route('/login')
def login():
    return render_template('login.html')



@app.route('/services')
def services():
    return render_template('services.html')
    
#Startng page of to create ec2 instance
@app.route('/launchec2')
def ec2():
    return render_template('ec2.html')

@app.route('/<path:path>')
def serve_ec2_static_files(path):
    return send_from_directory('static', path)


@app.route('/launch_instance', methods=['POST','GET'])
def launch_instance():
    # Get parameters from query string
    ami_id = request.args.get('ami_id')
    instance_type = request.args.get('instance_type')
    count = request.args.get('count')

    # Launch EC2 instance
    response = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=int(count),
        MaxCount=int(count)
    )

    instance_id = response['Instances'][0]['InstanceId']
    
    # Describe instances and count running instances
    instances_response = ec2_client.describe_instances()
    running_instances = 0
    for reservation in instances_response['Reservations']:
        for instance in reservation['Instances']:
            if instance['State']['Name'] == 'running':
                running_instances += 1
    
    return jsonify({
        'message': 'Instance launched successfully',
        'instance_id': instance_id,
        'running_instances': running_instances
    })

@app.route('/list_instances', methods=['GET'])
def list_instances():
    # Get state from query parameters
    state_filter = request.args.get('state')

    # Describe instances
    instances_response = ec2_client.describe_instances()
    instances = []
    for reservation in instances_response['Reservations']:
        for instance in reservation['Instances']:
            # Filter instances based on state if provided
            if state_filter:
                if instance['State']['Name'] == state_filter:
                    instance_info = {
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance['InstanceType'],
                        'state': instance['State']['Name']
                    }
                    instances.append(instance_info)
            else:
                instance_info = {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'state': instance['State']['Name']
                }
                instances.append(instance_info)
    
    return jsonify({
        'instances': instances
    })

@app.route('/instance_info', methods=['GET'])
def instance_info():
    # Get instance ID from query parameters
    instance_id = request.args.get('instance_id')
    
    # Describe instance based on instance ID
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    if 'Reservations' in response:
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_info = {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'state': instance['State']['Name']
                }
                return jsonify(instance_info)
    return jsonify({'message': 'Instance not found'})

@app.route('/delete_instance', methods=['DELETE','GET'])
def delete_instance():
    # Get instance ID from query parameters
    instance_id = request.args.get('instance_id')
    
    # Terminate instance based on instance ID
    ec2_client.terminate_instances(InstanceIds=[instance_id])
    
    return jsonify({'message': 'Instance terminated'})

@app.route('/delete_all_instances', methods=['DELETE','GET'])
def delete_all_instances():
    # Describe instances
    instances_response = ec2_client.describe_instances()
    instance_ids = []
    for reservation in instances_response['Reservations']:
        for instance in reservation['Instances']:
            instance_ids.append(instance['InstanceId'])
    
    # Terminate all instances
    ec2_client.terminate_instances(InstanceIds=instance_ids)
    
    return jsonify({'message': 'All instances terminated'})

@app.route('/stop_instance', methods=['PUT','GET'])
def stop_instance():
    # Get instance ID from request
    instance_id = request.args.get('instance_id')

    # Stop the instance
    ec2_client.stop_instances(InstanceIds=[instance_id])

    return jsonify({'message': 'Instance stopped successfully'})

@app.route('/start_instance', methods=['PUT','GET'])
def start_instance():
    # Get instance ID from request
    instance_id = request.args.get('instance_id')

    # Start the instance
    ec2_client.start_instances(InstanceIds=[instance_id])

    return jsonify({'message': 'Instance started successfully'})

@app.route('/terminate_instance', methods=['DELETE','GET'])
def terminate_instance():
    # Get instance ID from request
    instance_id = request.args.get('instance_id')

    # Terminate the instance
    ec2_client.terminate_instances(InstanceIds=[instance_id])

    return jsonify({'message': 'Instance terminated successfully'})



@app.route('/modify_instance_type', methods=['PUT','GET'])
def modify_instance_type():
    # Get instance ID and new instance type from request
    instance_id = request.args.get('instance_id')
    new_instance_type = request.args.get('new_instance_type')

    # Modify instance type
    ec2_client.modify_instance_attribute(
        InstanceId=instance_id,
        InstanceType={
            'Value': new_instance_type
        }
    )

    return jsonify({'message': 'Instance type modified successfully'})

@app.route('/update_instance_tags', methods=['PUT','GET'])
def update_instance_tags():
    # Get instance ID and new tags from request
    instance_id = request.args.get('instance_id')
    new_tags = request.json  # Assuming the request body contains the new tags in JSON format

    # Convert the dictionary of tags into a list of dictionaries
    tags_list = [{'Key': key, 'Value': value} for key, value in new_tags.items()]

    # Update instance tags
    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=tags_list
    )

    return jsonify({'message': 'Instance tags updated successfully'})


########### Create VPC    #######
@app.route('/vpc')
def vpc():
    return render_template('vpc.html')

@app.route('/static/<path:path>')
def serve_static_files(path):
    return send_from_directory('static', path)

@app.route('/create_vpc', methods=['POST','GET'])
def create_vpc():
    try:
        cidr_block = request.form['cidr_block']

        # Create VPC
        vpc_response = vpc_client.create_vpc(
            CidrBlock=cidr_block,
            AmazonProvidedIpv6CidrBlock=False
        )

        vpc_id = vpc_response['Vpc']['VpcId']

        return jsonify({'message': f'VPC with ID {vpc_id} created successfully.'}), 200
    except Exception as e:
        # Add detailed error logging
        app.logger.error(f"Error creating VPC: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
#### create s3 Bucket

@app.route('/s3')
def s3():
    return render_template('s3.html')

@app.route('/static/<path:path>')
def serve_s3_static_files(path):
    return send_from_directory('static', path)

@app.route('/create_bucket', methods=['POST','GET'])
def create_bucket():
    try:
        # Generate a unique bucket name
        bucket_name = f"bucket-{uuid.uuid4()}"
        s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': AWS_REGION})
        return jsonify({"message": "Bucket created successfully", "bucket_name": bucket_name}), 201
    except Exception as e:
        app.logger.error(f"Error creating bucket: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/delete_bucket/<bucket_name>', methods=['DELETE','GET'])
def delete_bucket(bucket_name):
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        return jsonify({"message": "Bucket deleted successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error deleting bucket: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/upload_file/<bucket_name>', methods=['POST','GET'])
def upload_file(bucket_name):
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    try:
        s3_client.upload_fileobj(file, bucket_name, file.filename)
        return jsonify({"message": "File uploaded successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error uploading file: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
###### SQS API code

@app.route('/sqs')
def sqs_home():
    return render_template('sqs.html')

@app.route('/static/<path:path>')
def serve_sqs_static_files(path):
    return send_from_directory('static', path)

@app.route('/create_queue', methods=['POST'])
def create_queue():
    try:
        data = request.json
        
        # Required parameter
        queue_name = data.get('queue_name')
        if not queue_name:
            return jsonify({'error': 'Queue name is required'}), 400
        
        # Optional parameters
        attributes = data.get('attributes', {})
        tags = data.get('tags', {})
        
        # Create the SQS queue
        response = sqs.create_queue(
            QueueName=queue_name,
            Attributes=attributes,
            tags=tags
        )
        
        return jsonify({'queue_url': response['QueueUrl']}), 201
    
    except NoCredentialsError:
        return jsonify({'error': 'AWS credentials not found'}), 403
    except PartialCredentialsError:
        return jsonify({'error': 'Incomplete AWS credentials'}), 403
    except Exception as e:
        app.logger.error(f"Error creating SQS queue: {str(e)}")
        return jsonify({'error': str(e)}), 500  

##### SNS code
@app.route('/sns')
def sns():
    return render_template('sns.html')

@app.route('/create_topic', methods=['POST'])
def create_topic():
    try:
        topic_name = request.json.get('topic_name')
        response = sns_client.create_topic(Name=topic_name)
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError):
        return jsonify({'error': 'AWS credentials not found'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list_topics', methods=['GET'])
def list_topics():
    try:
        response = sns_client.list_topics()
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError):
        return jsonify({'error': 'AWS credentials not found'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/publish_message', methods=['POST'])
def publish_message():
    try:
        topic_arn = request.json.get('topic_arn')
        message = request.json.get('message')
        response = sns_client.publish(TopicArn=topic_arn, Message=message)
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError):
        return jsonify({'error': 'AWS credentials not found'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_topic', methods=['DELETE'])
def delete_topic():
    try:
        topic_arn = request.json.get('topic_arn')
        response = sns_client.delete_topic(TopicArn=topic_arn)
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError):
        return jsonify({'error': 'AWS credentials not found'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#### dynamoDB code
@app.route('/dynamodb')
def home():
    return render_template('dynamodb.html')

@app.route('/create_table', methods=['POST'])
def create_table():
    data = request.get_json()
    table_name = data.get('table_name')
    key_schema = data.get('key_schema')
    attribute_definitions = data.get('attribute_definitions')
    provisioned_throughput = data.get('provisioned_throughput')
    
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            ProvisionedThroughput=provisioned_throughput
        )
        table.wait_until_exists()
        return jsonify({'message': f'Table {table_name} created successfully!'}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'error': 'Credentials not available'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/insert_item', methods=['POST'])
def insert_item():
    data = request.get_json()
    table_name = data.get('table_name')
    item = data.get('item')
    
    try:
        table = dynamodb.Table(table_name)
        table.put_item(Item=item)
        return jsonify({'message': 'Item inserted successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/get_item', methods=['GET'])
def get_item():
    table_name = request.args.get('table_name')
    key = request.args.get('key')
    
    try:
        table = dynamodb.Table(table_name)
        response = table.get_item(Key=key)
        if 'Item' in response:
            return jsonify(response['Item']), 200
        else:
            return jsonify({'error': 'Item not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_item', methods=['DELETE'])
def delete_item():
    data = request.get_json()
    table_name = data.get('table_name')
    key = data.get('key')
    
    try:
        table = dynamodb.Table(table_name)
        table.delete_item(Key=key)
        return jsonify({'message': 'Item deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_table', methods=['DELETE'])
def delete_table():
    table_name = request.get_json().get('table_name')
    
    try:
        table = dynamodb.Table(table_name)
        table.delete()
        return jsonify({'message': f'Table {table_name} deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

####LB code 
@app.route('/lb')
def lb():
    return render_template('lb.html')

@app.route('/create-load-balancer', methods=['POST'])
def create_load_balancer():
    data = request.json
    name = data.get('name')
    subnets = data.get('subnets')
    security_groups = data.get('security_groups', [])
    scheme = data.get('scheme', 'internet-facing')
    tags = data.get('tags', [])

    response = elb_client.create_load_balancer(
        Name=name,
        Subnets=subnets,
        SecurityGroups=security_groups,
        Scheme=scheme,
        Tags=tags
    )
    
    return jsonify(response)

@app.route('/describe-load-balancers', methods=['GET'])
def describe_load_balancers():
    response = elb_client.describe_load_balancers()
    return jsonify(response)

@app.route('/delete-load-balancer', methods=['DELETE'])
def delete_load_balancer():
    data = request.json
    load_balancer_arn = data.get('load_balancer_arn')

    response = elb_client.delete_load_balancer(
        LoadBalancerArn=load_balancer_arn
    )
    
    return jsonify(response)
##### SES (simple email service) code

@app.route('/ses')
def ses():
    return render_template('ses.html')

@app.route('/send-email', methods=['POST'])
def send_email():
    data = request.get_json()
    source = data.get('source')
    to_addresses = data.get('to_addresses')
    subject = data.get('subject')
    body = data.get('body')

    try:
        response = ses_client.send_email(
            Source=source,
            Destination={
                'ToAddresses': to_addresses
            },
            Message={
                'Subject': {
                    'Data': subject
                },
                'Body': {
                    'Text': {
                        'Data': body
                    }
                }
            }
        )
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list-verified-emails', methods=['GET'])
def list_verified_emails():
    try:
        response = ses_client.list_verified_email_addresses()
        return jsonify(response['VerifiedEmailAddresses']), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email_address = data.get('email_address')

    try:
        response = ses_client.verify_email_identity(
            EmailAddress=email_address
        )
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

### codebuild API code

@app.route('/codebuild')
def codebuild():
    return render_template('codebuild.html')

@app.route('/create_project', methods=['POST'])
def create_project():
    data = request.json
    try:
        response = codebuild_client.create_project(
            name=data['name'],
            source={
                'type': data['source']['type'],
                'location': data['source']['location']
            },
            artifacts={
                'type': 'NO_ARTIFACTS'
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/standard:4.0',
                'computeType': 'BUILD_GENERAL1_SMALL'
            },
            serviceRole=data['serviceRole']
        )
        return jsonify(response), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/delete_project', methods=['DELETE'])
def delete_project():
    data = request.json
    try:
        response = codebuild_client.delete_project(
            name=data['name']
        )
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/list_projects', methods=['GET'])
def list_projects():
    try:
        response = codebuild_client.list_projects()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/ecs')
def ecs():
    return render_template('ecs.html')


@app.route('/ecs/create_cluster', methods=['POST'])
def create_cluster():
    cluster_name = request.json.get('cluster_name')
    if not cluster_name:
        return jsonify({"error": "Cluster name is required"}), 400

    try:
        response = ecs_client.create_cluster(clusterName=cluster_name)
        return jsonify(response), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/ecs/list_clusters', methods=['GET'])
def list_clusters():
    try:
        response = ecs_client.list_clusters()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/ecs/delete_cluster', methods=['DELETE'])
def delete_cluster():
    cluster_name = request.json.get('cluster_name')
    if not cluster_name:
        return jsonify({"error": "Cluster name is required"}), 400

    try:
        response = ecs_client.delete_cluster(cluster=cluster_name)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/codedeploy')
def codedeploy():
    return render_template('codedeploy.html')


@app.route('/codedeploy/create-application', methods=['POST'])
def create_application():
    data = request.get_json()
    application_name = data.get('application_name')

    try:
        response = client.create_application(
            applicationName=application_name
        )
        return jsonify(response), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/codedeploy/delete-application', methods=['DELETE'])
def delete_application():
    data = request.get_json()
    application_name = data.get('application_name')

    try:
        response = client.delete_application(
            applicationName=application_name
        )
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/codedeploy/list-applications', methods=['GET'])
def list_applications():
    try:
        response = client.list_applications()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/codecommit')
def codecommit():
    return render_template('codecommit.html')

# Create a new CodeCommit repository
@app.route('/create-repo', methods=['POST'])
def create_repo():
    repo_name = request.json.get('repositoryName')
    if not repo_name:
        return jsonify({"error": "repositoryName is required"}), 400

    try:
        response = codecommit_client.create_repository(
            repositoryName=repo_name,
            repositoryDescription=request.json.get('repositoryDescription', '')
        )
        return jsonify(response), 201
    except ClientError as e:
        return jsonify({"error": str(e)}), 500

# Get information about a CodeCommit repository
@app.route('/get-repo', methods=['GET'])
def get_repo():
    repo_name = request.args.get('repositoryName')
    if not repo_name:
        return jsonify({"error": "repositoryName is required"}), 400

    try:
        response = codecommit_client.get_repository(
            repositoryName=repo_name
        )
        return jsonify(response), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 500

# Delete a CodeCommit repository
@app.route('/delete-repo', methods=['DELETE'])
def delete_repo():
    repo_name = request.json.get('repositoryName')
    if not repo_name:
        return jsonify({"error": "repositoryName is required"}), 400

    try:
        response = codecommit_client.delete_repository(
            repositoryName=repo_name
        )
        return jsonify(response), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 500

### List all CodeCommit repositories
@app.route('/list-repos', methods=['GET'])
def list_repos():
    try:
        response = codecommit_client.list_repositories()
        return jsonify(response), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 500


@app.route('/iam')
def iam():
    return render_template('iam.html')


@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.json.get('username')
    try:
        response = iam_client.create_user(UserName=username)
        return jsonify(response), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    username = request.json.get('username')
    try:
        response = iam_client.delete_user(UserName=username)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/list_users', methods=['GET'])
def list_users():
    try:
        response = iam_client.list_users()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/create_group', methods=['POST'])
def create_group():
    groupname = request.json.get('groupname')
    try:
        response = iam_client.create_group(GroupName=groupname)
        return jsonify(response), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/list_groups', methods=['GET'])
def list_groups():
    try:
        response = iam_client.list_groups()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/delete_group', methods=['DELETE'])
def delete_group():
    groupname = request.json.get('groupname')
    try:
        response = iam_client.delete_group(GroupName=groupname)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
