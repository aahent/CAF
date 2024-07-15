// Start of S3 Bucket Code 

document.getElementById('createBucketBtn').addEventListener('click', () => {
    fetch('/create_bucket', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerText = JSON.stringify(data);
    })
    .catch(error => {
        document.getElementById('response').innerText = 'Error creating bucket';
        console.error('Error:', error);
    });
});

document.getElementById('deleteBucketBtn').addEventListener('click', () => {
    const bucketName = document.getElementById('deleteBucketName').value;
    fetch(`/delete_bucket/${bucketName}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerText = JSON.stringify(data);
    })
    .catch(error => {
        document.getElementById('response').innerText = 'Error deleting bucket';
        console.error('Error:', error);
    });
});

document.getElementById('uploadFileBtn').addEventListener('click', () => {
    const bucketName = document.getElementById('uploadBucketName').value;
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    const formData = new FormData();
    formData.append('file', file);

    fetch(`/upload_file/${bucketName}`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').innerText = JSON.stringify(data);
    })
    .catch(error => {
        document.getElementById('response').innerText = 'Error uploading file';
        console.error('Error:', error);
    });
});


document.getElementById('launchForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const ami_id = document.getElementById('ami_id').value;
    const instance_type = document.getElementById('instance_type').value;
    const count = document.getElementById('count').value;

//
    fetch(`/launch_instance?ami_id=${ami_id}&instance_type=${instance_type}&count=${count}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        alert(`Instance launched: ${data.instance_id}`);
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('listInstancesButton').addEventListener('click', function() {
    fetch('/list_instances')
    .then(response => response.json())
    .then(data => {
        const instancesList = document.getElementById('instancesList');
        instancesList.innerHTML = '<h3>Instances:</h3>';
        data.instances.forEach(instance => {
            instancesList.innerHTML += `<p>ID: ${instance.instance_id}, Type: ${instance.instance_type}, State: ${instance.state}</p>`;
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('instanceOperationForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const instance_id = document.getElementById('instance_id').value;
    const operation = document.getElementById('operation').value;
    let endpoint = '';

    if (operation === 'start') {
        endpoint = '/start_instance';
    } else if (operation === 'stop') {
        endpoint = '/stop_instance';
    } else if (operation === 'terminate') {
        endpoint = '/delete_instance';
    }

    fetch(`${endpoint}?instance_id=${instance_id}`, {
        method: 'PUT'
    })
    .then(response => response.json())
    .then(data => {
        alert(`Instance ${operation}d successfully`);
    })
    .catch(error => {
        console.error('Error:', error);
    });
});



// end of ec2 code

// VPC code started

document.getElementById("vpcForm").addEventListener("submit", function(event) {
    event.preventDefault();

    var cidrBlock = document.getElementById("cidr_block").value;

    fetch("/create_vpc", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "cidr_block=" + encodeURIComponent(cidrBlock)
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            showPopup(data.message);
        } else if (data.error) {
            showPopup(data.error);
        }
    })
    .catch(error => {
        console.error("Error:", error);
        showPopup("An error occurred while creating the VPC.");
    });
});

function showPopup(message) {
    var popup = document.createElement("div");
    popup.classList.add("popup");
    popup.innerText = message;

    var closeButton = document.createElement("button");
    closeButton.innerText = "Close";
    closeButton.addEventListener("click", function() {
        popup.remove();
    });

    popup.appendChild(closeButton);
    document.body.appendChild(popup);
}


// end of vpc code

