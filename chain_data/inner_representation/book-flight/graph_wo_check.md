graph TD
    B --> C{UserValidation返回值}
    H --> C{UserValidation返回值}
    C -->|True| E[BookTargetFlight]
    C -->|True| K[BookCtripFlight]
    C -->|False| Z
    E --> I{BookFlight返回值}
    K --> I
    I --> |True| J[SendUserInformation]
    I --> |False| E
    I --> |False| K
    J --> M[完成订票任务]